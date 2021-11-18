import configparser
import email.parser
import email.policy
import io
import re
import xml.etree.ElementTree as ET
from email.message import EmailMessage
from urllib.parse import urlparse, unquote

import clamd
import requests
import urllib3
from flask import Flask, Response, abort, request

__version__ = "0.6"

ALL_METHODS = [
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "PATCH",
]

reg_retrieve_document = re.compile(b":RetrieveDocumentSetRequest</Action>")

# to prevent flooding log
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
config = configparser.ConfigParser()
config.read("av_gate.ini")

loglevel = config["config"].get("log_level", "ERROR")
app.logger.setLevel(loglevel)

clamav = clamd.ClamdUnixSocket(path=config["config"]["clamd_socket"])


@app.route("/connector.sds", methods=["GET"])
def connector_sds():
    """replace the endpoint for PHRService with our address"""
    # <si:Service Name="PHRService">
    # <si:EndpointTLS Location="https://kon-instanz1.titus.ti-dienste.de:443/soap-api/PHRService/1.3.0"/>

    upstream = request_upstream(warn=False)

    xml = ET.fromstring(upstream.content)
    e = xml.find("{*}ServiceInformation/{*}Service[@Name='PHRService']//{*}EndpointTLS")
    if not e:
        KeyError("connector.sds does not contain PHRService location.")

    previous_url = urlparse(e.attrib["Location"])
    e.attrib["Location"] = f"{previous_url.scheme}://{request.host}{previous_url.path}"

    return create_response(ET.tostring(xml), upstream)


@app.route("/<path:path>", methods=ALL_METHODS)
def soap(path):
    """Scan AV on xop documents for retrieveDocumentSetRequest"""
    upstream = request_upstream()
    
    data = run_antivirus(upstream) or upstream.content

    return create_response(data, upstream)


def request_upstream(warn=True) -> Response:
    """Request to real Konnektor"""
    request_ip = request.headers["X-real-ip"]
    app.logger.info(f"header host {request.host}")
    port = request.host.split(":")[1] if ":" in request.host else "443"

    client = f"{request_ip}:{port}"

    if config.has_section(client):
        cfg = config[client]
    else:
        fallback = "*:" + port
        if not config.has_section(fallback):
            app.logger.error(f"Client {client} not found in av_gate.ini")
            abort(500)
        else:
            cfg = config[fallback]

    konn = cfg["Konnektor"]
    url = konn + request.path
    data = request.get_data()

    # client cert
    cert = None
    if cfg.get("ssl_cert"):
        cert = (cfg["ssl_cert"], cfg["ssl_key"])
    verify = cfg.getboolean("ssl_verify")

    headers = {
        key: value
        for key, value in request.headers.items()
        if key not in ("X-Real-Ip", "Host")
    }

    try:
        response = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            data=data,
            cert=cert,
            verify=verify,
        )

        if warn and bytes(konn, "ASCII") in response.content:
            app.logger.warning(
                f"Found Konnektor Address in response: {konn} - {request.path}"
            )

        return response

    except Exception as err:
        app.logger.error(err)
        abort(502)


def create_response(data, upstream: Response) -> Response:
    """Create new response with copying headers from origin response"""
    response = Response(data)

    # copy headers from upstream response
    for k, v in upstream.headers.items():
        if k not in ["Transfer-Encoding", "Content-Length"]:
            response.headers[k] = v

    # overwrite content-length with current length
    response.headers["Content-Length"] = str(response.content_length)

    return response


def run_antivirus(res: Response):
    """Remove document when virus was found"""
    
    # only interested in multipart
    if not res.headers["Content-Type"].startswith("multipart"):
        return
        
    # add Header for content-type
    body = (
        bytes(f"Content-Type: {res.headers['Content-Type']}\r\n\r\n\r\n", "ascii")
        + res.content
    )
    msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(body)
    soap_part: EmailMessage = next(msg.iter_parts())
    xml = ET.fromstring(soap_part.get_content())
    response_xml = xml.find("{*}Body/{*}RetrieveDocumentSetResponse")
    
    # only interested in RetrieveDocumentSet
    if response_xml is None:
        return
    
    virus_atts = []

    for att in msg.iter_attachments():
        scan_res = clamav.instream(io.BytesIO(att.get_content()))["stream"]
        content_id = att["Content-ID"]
        if scan_res[0] != "OK":
            app.logger.info(f"virus found {content_id} : {scan_res}")
            virus_atts.append(content_id)

    if virus_atts:
        xml_resp = response_xml.find("{*}RegistryResponse")
        xml_ns = re.search("{.*}", xml_resp.tag)[0]
        xml_errlist = ET.Element(f"{xml_ns}RegistryErrorList")
        xml_resp.append(xml_errlist)

        xml_documents = {
            unquote(d.find("{*}Document/{*}Include").attrib["href"])[4:]: d
            for d in response_xml.findall("{*}DocumentResponse")
        }

        attachments = list(msg.iter_attachments())
        msg.set_payload([soap_part])
        for att in attachments:
            content_id = att["Content-ID"]
            if content_id in virus_atts:
                document_xml = xml_documents[content_id[1:-1]]
                document_id = document_xml.find("{*}DocumentUniqueId").text
                app.logger.info(f"removed document {document_id}")

                # add error msg
                err_text = (
                    f"Document was detected as malware for uniqueId '{document_id}'."
                )
                xml_errlist.append(
                    ET.Element(
                        f"{xml_ns}RegistryError",
                        attrib={
                            "codeContext": err_text,
                            "errorCode": "XDSDocumentUniqueIdError",  # from RetrieveDocumentSetResponse
                            # "errorCode": "XDSMissingDocument", # from AdHocQueryResponse
                            "severity": "urn:oasis:names:tc:ebxml-regrep:ErrorSeverityType:Error",
                        },
                        text=err_text,
                    )
                )

                # remove document reference
                response_xml.remove(document_xml)

            else:
                msg.attach(att)

        if len(msg.get_payload()) > 1:
            xml_resp.attrib[
                "status"
            ] = "urn:ihe:iti:2007:ResponseStatusType:PartialSuccess"
        else:
            xml_resp.attrib[
                "status"
            ] = "urn:oasis:names:tc:ebxml-regrep:ResponseStatusType:Failure"
            xml_errlist.append(
                ET.Element(
                    f"{xml_ns}RegistryError",
                    attrib={
                        "severity": "urn:oasis:names:tc:ebxml-regrep:ErrorSeverityType:Error",
                        "errorCode": "XDSRegistryMetadataError",
                        "codeContext": "No documents found for unique ids in request",
                    },
                    text="No documents found for unique ids in request",
                )
            )

        soap_part.set_payload(ET.tostring(xml), soap_part.get_content_maintype())
        body = msg.as_bytes()

        # remove headers of envelope
        body = body[body.find(b"\n\n") + 2 :]

        return body


if __name__ == "__main__":
    # only relevant, when started directly.
    # production runs uwsgi
    app.run(host="0.0.0.0", debug=True, port=5001)
