import configparser
import email.generator
import email.parser
import email.policy
import io
import logging
import os
import re
import socket
import ssl
import types
from email.message import EmailMessage
from typing import Any, Callable, Generator, List, cast
from urllib.parse import unquote, urlparse

import flask
import lxml.etree as ET
import requests
import urllib3

__version__ = "1.11"

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

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}" + rb"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# to prevent flooding log
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = flask.Flask(__name__)

config = configparser.ConfigParser()

config.read("avgate.ini")

loglevel = config.get("config", "log_level", fallback="INFO")
logging.basicConfig(
    level=loglevel, format="[%(asctime)s] %(levelname)-8s in %(module)s: %(message)s"
)

logger = logging.getLogger(__name__)
logger.info(f"avgate {__version__}")
logger.debug(list(config["config"].items()))

CONTENT_MAX = config["config"].getint("content_max", 800)
REMOVE_MALICIOUS = config["config"].getboolean("remove_malicious", False)
ALL_PNG_MALICIOUS = config["config"].getboolean("all_png_malicious", False)
ALL_PDF_MALICIOUS = config["config"].getboolean("all_pdf_malicious", False)

clamav_sock: Any = None

if config.has_option("config", "clamd_socket"):
    import clamd  # type: ignore

    global clamav
    clamdPath = config["config"]["clamd_socket"]
    clamav: clamd.ClamdUnixSocket = clamd.ClamdUnixSocket(clamdPath)


@app.route("/connector.sds")
def connector_sds():
    """replace the endpoint for PHRService with our address"""
    # <si:Service Name="PHRService">
    # <si:EndpointTLS Location="https://kon-instanz1.titus.ti-dienste.de:443/ws/PHRService/1.3.0"/>

    logger.debug(f"Client Cert: {flask.request.headers.get('X-Client-Cert') or None}")
    client_config = get_client_config()
    with request_upstream(client_config, warn=False) as upstream:
        xml = ET.fromstring(upstream.content)

        if client_config.getboolean("proxy_all_services", False):
            for e in xml.findall("{*}ServiceInformation/{*}Service//{*}EndpointTLS"):
                previous_url = urlparse(e.attrib["Location"])
                e.attrib["Location"] = (
                    f"{previous_url.scheme}://{flask.request.host}{previous_url.path}"
                )

        for e in xml.findall(
            "{*}ServiceInformation/{*}Service[@Name='PHRService']//{*}EndpointTLS"
        ):
            previous_url = urlparse(e.attrib["Location"])
            e.attrib["Location"] = (
                f"{previous_url.scheme}://{flask.request.host}{previous_url.path}"
            )
            global phr_service_path
            phr_service_path = previous_url.path
        else:
            KeyError("connector.sds does not contain PHRService location.")

        return create_response(ET.tostring(xml), upstream)


@app.route("/<path:path>", methods=ALL_METHODS)
def switch(path):
    """Entrypoint with filter for PHRService"""
    if "PHRService" in path:
        logger.debug("start PHRService")
        v = phr_service()
        logger.debug("end PHRService")
        return v
    else:
        return other()


@app.route("/favicon.ico")
def fav():
    return "OK\n"


@app.route("/health")
def health():
    """Health check"""
    res = check_clamav()
    res += check_icap()
    if res:
        return flask.Response(res, mimetype="text/plain", status=503)
    return "OK\n"


@app.route("/icap")
def icap():
    """Running tests on icap directly"""
    icap = get_icap(EICAR)
    logger.debug(f"icap length: {len(icap)}")
    return icap


@app.post("/icap")
def icap_post():
    """Running icap with post data"""
    return get_icap(flask.request.get_data())


@app.route("/check")
def check():
    """Health check for Konnektors"""
    res = ""
    err_count = 0
    for client in config.sections():
        if client == "config":
            continue
        client_config = config[client]
        konn = client_config["konnektor"]

        # client cert
        cert = None
        if client_config.get("ssl_cert"):
            cert = (client_config["ssl_cert"], client_config["ssl_key"])
        verify = client_config.get("ssl_verify", "on").lower() != "off"

        try:
            test = requests.request(
                method=flask.request.method,
                url=konn + "/connector.sds",
                cert=cert,
                verify=verify,
                timeout=3,
            )

            if test.ok:
                res += f"{konn}: OK \n"
            else:
                err_count += 1
                res += f"{client} {konn}: {test.status_code} \n"
                logging.warn(
                    f"check failed for Konnektor {client} {konn} {test.status_code} {test.text}"
                )

        except Exception as err:
            err_count += 1
            res += f"{client} {konn}: {err} \n"
            logger.warning(f"check failed for Konnektor: {client} {konn} {err}")

    return flask.Response(res, mimetype="text/plain", status=503 if err_count else 200)


def check_clamav() -> str:
    clamd_path = config["config"].get("clamd_socket")
    if not clamd_path:
        return ""

    test = clamav_sock.ping()
    if test != "PONG":
        logger.warning(f"Healtchckeck failed for clamav: {test}")
        return "clamav: no ping\n"
    return ""


def check_icap() -> str:
    icap_host = config["config"].get("icap_host")
    if not icap_host:
        return ""

    try:
        scan_file_icap(b"ping\r\n")
        return ""
    except Exception as err:
        logger.warning(f"Healtcheck failed for icap: {err}")
        return "icap: failed\n"


def phr_service() -> flask.Response:
    """Scan AV on xop documents for retrieveDocumentSetRequest"""
    client_config = get_client_config()
    with request_upstream(client_config) as upstream:
        data = run_antivirus(upstream)

        if not data:
            logger.debug("no new body, copying content from konnektor")
            data = upstream.content

        if EICAR in data:
            logger.error("found EICAR signature")

        response = create_response(data, upstream)

        return response


def other() -> flask.wrappers.Response:
    """Streamed forward without scan"""
    client_config = get_client_config()
    with request_upstream(client_config, stream=True) as upstream:
        response = create_response(upstream.iter_content(), upstream)
        return response


def request_upstream(
    client_config, warn=True, stream=False
) -> requests.models.Response:
    """Request to real Konnektor"""

    konn = client_config["Konnektor"]
    url = konn + flask.request.path
    data = flask.request.stream if stream else flask.request.get_data()

    # client cert
    cert = None
    if client_config.get("ssl_cert"):
        cert = (client_config["ssl_cert"], client_config["ssl_key"])
    verify = client_config.get("ssl_verify", "on").lower() != "off"

    headers = {
        key: value
        for key, value in flask.request.headers.items()
        if key not in ("X-Real-Ip", "Host")
    }

    try:
        response = requests.request(
            method=flask.request.method,
            url=url,
            headers=headers,
            data=data,
            cert=cert,
            verify=verify,
            stream=stream,
        )

        if warn and not stream and bytes(konn, "ascii") in response.content:
            logger.warning(
                f"Found Konnektor Address in response: {konn} - {flask.request.url}"
            )

        if not response.ok:
            logger.warning(
                f"Error from Konnektor: {response.url} - {response.status_code} {response.reason}"
            )
            logger.warning(f"Response: {response.content.decode()}")
            logger.warning(f"Cert: {flask.request.headers.get('X-Client-Cert')}")

        return response

    except Exception as err:
        logger.error(err)
        flask.abort(502)


def get_client_config() -> configparser.SectionProxy:
    request_ip = flask.request.headers.get(
        "X-real-ip", flask.request.host.split(":")[0]
    )
    port = flask.request.host.split(":")[1] if ":" in flask.request.host else "443"

    client = f"{request_ip}:{port}"
    logger.debug(f"client {client}")

    if config.has_section(client):
        return config[client]
    if config.has_section(f"*:{port}"):
        return config[f"*:{port}"]
    if config.has_section("default"):
        return config["default"]
    else:
        logger.error(f"Client {client} or default not found in avgate.ini")
        flask.abort(503)


def create_response(
    data, upstream: requests.models.Response
) -> flask.wrappers.Response:
    """Create new response with copying headers from origin response"""
    headers = {
        k: v
        for (k, v) in upstream.headers.items()
        if k
        not in (
            "Content-Length",
            "Connection",
            "Date",
            "Transfer-Encoding",
            "Mimetype",
            "Content-Type",
        )
    }

    if isinstance(data, types.FunctionType):
        response = flask.Response(
            response=flask.stream_with_context(data()),
            status=upstream.status_code,
            headers=headers,
            mimetype=upstream.headers.get("Mimetype"),
            content_type=upstream.headers.get("Content-Type"),
            direct_passthrough=True,
        )
    else:
        response = flask.Response(
            response=data,
            status=upstream.status_code,
            headers=headers,
            mimetype=upstream.headers.get("Mimetype"),
            content_type=upstream.headers.get("Content-Type"),
            direct_passthrough=True,
        )

    return response


def run_antivirus(res: requests.models.Response):
    """Remove or exchange document when virus was found"""

    # only interested in multipart
    if not res.headers["Content-Type"].lower().startswith("multipart"):
        return

    # add Header for content-type
    body = (
        bytes(f"Content-Type: {res.headers['Content-Type']}\r\n\r\n\r\n", "ascii")
        + res.content
    )
    msg = cast(
        EmailMessage,
        email.parser.BytesParser(policy=email.policy.default).parsebytes(body),
    )
    soap_part = cast(EmailMessage, next(msg.iter_parts()))
    xml = ET.fromstring(soap_part.get_payload())
    response_xml = xml.find("{*}Body/{*}RetrieveDocumentSetResponse")

    # only interested in RetrieveDocumentSet
    if response_xml is None:
        logger.info(f"XML NOT FOUND RetrieveDocument {soap_part.get_payload()[:200]}")
        return

    malicious_content_ids = list(get_malicious_content_ids(msg))

    if malicious_content_ids:
        xml_resp = response_xml.find("{*}RegistryResponse")
        assert xml_resp is not None
        m = re.search("{.*}", xml_resp.tag)
        assert m
        xml_ns = m[0]

        # ger errlist
        xml_errlist = xml_resp.find("{*}RegistryErrorList")
        if not xml_errlist:
            xml_errlist = ET.Element(f"{xml_ns}RegistryErrorList")
            xml_resp.append(xml_errlist)

        xml_documents = {}

        for doc in response_xml.findall("{*}DocumentResponse"):
            include = doc.find("{*}Document/{*}Include")
            assert include is not None
            href = cast(str, include.attrib["href"])
            assert href
            content_id = extract_id(href)
            xml_documents[content_id] = doc

        logger.debug(f"content_ids: {list(xml_documents.keys())}")

        attachments = cast(List[EmailMessage], list(msg.iter_attachments()))
        msg.set_payload([soap_part])
        for att in attachments:
            handle_attachment(
                msg,
                response_xml,
                malicious_content_ids,
                xml_ns,
                xml_errlist,
                xml_documents,
                att,
            )

        if REMOVE_MALICIOUS:
            fix_status(xml_resp, xml_errlist, xml_ns, msg)

    if malicious_content_ids:
        if REMOVE_MALICIOUS:
            soap_part.set_payload(ET.tostring(xml), charset="utf-8")
            del soap_part["MIME-Version"]

        payload = build_payload(msg, malicious_content_ids, res)

        return payload


def handle_attachment(
    msg: EmailMessage,
    response_xml: ET._Element,
    malicious_content_ids: List[str],
    xml_ns: str,
    xml_errlist: ET._Element,
    xml_documents: dict,
    att,
):
    """removes or replaces malicious attachment"""
    content_id = extract_id(att["Content-ID"])
    document_xml = xml_documents[content_id]
    unique_id_xml = document_xml.find("{*}DocumentUniqueId")
    assert unique_id_xml is not None
    document_id = unique_id_xml.text
    mimetype_xml = document_xml.find("{*}mimeType")
    assert mimetype_xml is not None
    mimetype = mimetype_xml.text

    if content_id in malicious_content_ids:
        if REMOVE_MALICIOUS:
            add_error_msg(document_xml, xml_errlist, xml_ns)
            # remove document reference
            response_xml.remove(document_xml)
            logger.info(f"document removed {content_id!r} {document_id!r}")

        else:
            # replace document
            logger.info(
                f"document replaced {content_id!r} {document_id!r} {mimetype!r}"
            )
            att.set_payload(get_replacement(mimetype))
            msg.attach(att)
    else:
        logger.debug(f"document untouched {content_id!r} {document_id!r}")
        msg.attach(att)


def get_malicious_content_ids(msg: EmailMessage) -> Generator[str, None, None]:
    """Extracting content_ids of malicious attachments"""
    for att in msg.iter_attachments():
        att = cast(EmailMessage, att)
        scan_res = scan_file(att.get_content())
        content_id = extract_id(att["Content-ID"])

        test_malicous = False
        if ALL_PNG_MALICIOUS and att.get_content().startswith(
            bytearray.fromhex("89504E470D0A1A0A")
        ):
            test_malicous = True
        if ALL_PDF_MALICIOUS and att.get_content().startswith(
            bytearray.fromhex("25504446")
        ):
            test_malicous = True

        if scan_res[0] != "OK" or test_malicous:
            logger.info(f"virus found {content_id} : {scan_res}")
            yield content_id
        else:
            logger.debug(f"scanned document {content_id} : {scan_res}")
            if EICAR in att.get_content():
                logger.error(f"EICAR was not detected by av {content_id}")


def extract_id(id: str) -> str:
    """Returns content_id without prefix and postfix"""
    id = unquote(id)

    if id.startswith("cid:"):
        id = id[4:]
    if id.startswith("<"):
        id = id[1:-1]
    if "@" in id:
        id = id[: id.index("@")]

    return id


def add_error_msg(document_id, xml_errlist, xml_ns):
    """Adds error message to SOAP message for given document"""
    err_text = f"Document was detected as malware for uniqueId '{document_id}'."
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


def fix_status(xml_resp, xml_errlist, xml_ns, msg):
    """Adds overall error message to SOAP response"""
    if len(msg.get_payload()) > 1:
        xml_resp.attrib["status"] = "urn:ihe:iti:2007:ResponseStatusType:PartialSuccess"
    else:
        xml_resp.attrib["status"] = (
            "urn:oasis:names:tc:ebxml-regrep:ResponseStatusType:Failure"
        )
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


def build_payload(
    msg: EmailMessage, malicious_content_ids: List[str], res: requests.models.Response
) -> bytes:
    """create payload based on original response with replacing only payoad for malicious_content_ids"""

    content_type = res.headers["Content-Type"]
    m = re.search('boundary="(.*?)"', content_type, re.I)
    assert m
    boundary = b"\r\n--" + bytes(m[1], "ascii")

    payload: List[bytes] = []
    for part in res.content.split(boundary):
        content_id = get_content_id(part)
        if content_id in malicious_content_ids or (
            content_id == "root.message" and REMOVE_MALICIOUS
        ):
            att = cast(
                EmailMessage,
                next(
                    (
                        a
                        for a in msg.iter_parts()
                        if content_id == extract_id(a.get("Content-ID", ""))
                    ),
                    None,
                ),
            )
            if att:
                content = att.get_content()
                payload.append(part.split(b"\r\n\r\n")[0] + b"\r\n\r\n" + content)
            else:
                logger.error(
                    f"Content-ID not present: {content_id} in {next(msg.iter_parts()).items()}"
                )

        else:
            payload.append(part)

    return boundary.join(payload)


def get_content_id(content: bytes):
    m = re.search(b"\r\nContent-ID: (.*?)\r\n", content, re.I)
    if m:
        return extract_id(m[1].decode("ascii"))


# create dictonary with mimetypes: filename
replacement_files = {
    os.path.splitext(dir_entry.name)[0].replace("_", "/"): dir_entry.path
    for dir_entry in os.scandir("avgate/replacements")
}


def get_replacement(mimetype) -> bytes:
    """get content for replacements"""
    filename = replacement_files.get(mimetype) or replacement_files["text/plain"]
    with open(filename, "rb") as f:
        return f.read()


def dump(dict):
    return "\n".join([f"{k}: {v}" for (k, v) in dict.items()])


# File Scanning


def get_file_scanner() -> Callable[[bytes], List[str | None]]:
    clamd_path = config["config"].get("clamd_socket")
    icap_host = config["config"].get("icap_host")

    if not clamd_path and not icap_host:
        raise AttributeError("Neither clamd nor icap is configured")
    if clamd_path and icap_host:
        raise AttributeError("Both, clamd and icap is configured")

    if clamd_path:
        # CLAMAV
        import clamd  # type: ignore

        global clamav_sock
        clamav_sock = clamd.ClamdUnixSocket(path=config["config"]["clamd_socket"])
        return scan_file_clamav
    else:
        # ICAP
        return scan_file_icap


def scan_file_clamav(content: bytes) -> List[str | None]:
    """return scan result, do use clamav socket"""
    if not isinstance(clamav_sock, clamd.ClamdUnixSocket):
        raise AttributeError("clamav socket is not configured")
    scan_res = clamav_sock.instream(io.BytesIO(content))["stream"]
    return scan_res


def scan_file_icap(content: bytes) -> List[str | None]:
    """return scan result, do use icap"""
    icap_response = get_icap(content)
    (first_block, second_block) = icap_response.split(b"\r\n\r\n", 1)
    first_line = first_block.partition(b"\r\n")[0]
    FOOTER_LENGTH = 7
    content_back = second_block.partition(b"\r\n")[2][:-FOOTER_LENGTH]

    # check icap status
    if first_line == b"ICAP/1.0 204 No modifications needed":
        return ["OK", None]

    if first_line != b"ICAP/1.0 200 OK":
        raise EnvironmentError("ICAP not OK", first_line)

    # check infection
    found = re.search(b"X-Infection-Found: .*Threat=(.*);", first_block)

    # real finding
    if found:
        return ["FOUND", found[1].decode()]

    # in case of 200 the content should be unchanged
    if content == content_back:
        logger.warning("ICAP returns 200 instead of 204 on unchanged content")
        return ["OK", None]

    # modified content without infection found
    logger.warning("ICAP modified content without findings")
    logger.debug(f"IN  ...{content[-100:].decode()}")
    logger.debug(f"OUT ...{content_back[-100:].decode()})")

    return ["OK", None]


def get_icap(content: bytes) -> bytes:
    """do icap request in RESPMOD"""
    icap_service = config["config"]["icap_service"]
    icap_host = config["config"]["icap_host"]
    icap_port = config["config"].getint("icap_port", 1344)
    icap_tls = config["config"].getboolean("icap_tls", False)

    req_hdr = "GET /resource HTTP/1.1\r\n"
    req_hdr += f"Host: {flask.request.host}\r\n"
    req_hdr += "\r\n"

    res_hdr = "HTTP/1.1 200 OK\r\n"
    res_hdr += f"Content-Length: {len(content)}\r\n"
    res_hdr += "\r\n"

    req = f"RESPMOD {icap_service} ICAP/1.0\r\n"
    req += f"Host: {icap_host}\r\n"
    # Encapsulated: lengths in decimal
    req += f"Encapsulated: req-hdr=0, res-hdr={len(req_hdr)}, res-body={len(req_hdr + res_hdr)}\r\n"
    req += "\r\n"

    rcv_chunks = []

    with _open_sock(icap_host, icap_port, icap_tls) as sock:
        sock.send(req.encode())
        sock.send(req_hdr.encode())
        sock.send(res_hdr.encode())
        sock.send(f"{len(content):x}\r\n".encode())  # length in hex
        sock.send(content)
        sock.send("\r\n0\r\n\r\n".encode())

        while True:
            data = sock.recv(4096)
            rcv_chunks.append(data)
            if not len(data) or data[-5:] == b"0\r\n\r\n":
                break

    return b"".join(rcv_chunks)


def _open_sock(host: str, port: int, tls: bool) -> socket.socket:
    """returns socket, with TLS if needed"""
    if tls:
        with socket.create_connection((host, port)) as sock:
            context = ssl.create_default_context()
            return context.wrap_socket(sock, server_hostname=host)
    else:
        return socket.create_connection((host, port))


scan_file = get_file_scanner()
