import configparser
import email.parser
import email.policy
import io
import re

import clamd
import requests
from flask import Flask, Response, request

__version__ = "0.3"

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

config = configparser.ConfigParser()
config.read("av_gate.ini")

clamav = clamd.ClamdUnixSocket(path=config["config"]["clamd_socket"])

reg_retrieve_document = re.compile(b"RetrieveDocumentSetRequest")
reg_phr_service_endpoint = re.compile(
    b'^(.*?<.+?:Service Name="PHRService">.*?<.+?:EndpointTLS Location="https://)(.*?)(/.*)$',
    re.DOTALL,
)

app = Flask(__name__)
app.logger.setLevel("INFO")


@app.route("/connector.sds", methods=["GET"])
def connector_sds():
    """resplace the endpoint für PHRService with our address"""
    # <si:Service Name="PHRService">
    # <si:EndpointTLS Location="https://kon-instanz1.titus.ti-dienste.de:443/soap-api/PHRService/1.3.0"/>
    response = request_upstream()

    m = reg_phr_service_endpoint.match(response.content)
    if not m:
        KeyError("connector.sds does not contain PHRService location.")

    data = m.group(1) + bytes(request.host, "ASCII") + m.group(3)

    return create_response(data)


@app.route("/<path:path>", methods=ALL_METHODS)
def soap(path):
    upstream = request_upstream()

    if reg_retrieve_document.search(request.get_data()):
        data = run_antivirus(upstream) or upstream.content
    else:
        data = upstream.content

    return create_response(data, upstream)


def request_upstream() -> Response:
    remote_addr = request.remote_addr

    if not config.get(remote_addr):
        raise KeyError(f"Client ${remote_addr} not found in av_gate.ini")

    cfg = config[remote_addr]
    konn = cfg["Konnektor"]
    url = f"https://{konn}{request.path}"
    data = request.get_data()
    cert = None
    if cfg.get("proxy_ssl_cert"):
        cert = (cfg["proxy_ssl_cert"], cfg["proxy_ssl_key"])
    verify = cert != None

    response = requests.request(
        method=request.method,
        url=url,
        headers=request.headers,
        data=data,
        cert=cert,
        verify=verify,
    )

    if bytes(konn, "ASCII") in response.content:
        app.logger.warn(f"Found Konnektor Address in response: {konn} - {request.path}")

    return response


def create_response(data, upstream: Response) -> Response:
    response = Response(data)

    # copy headers from upstream response
    for k, v in upstream.headers.items():
        if k not in ["Transfer-Encoding", "Content-Length"]:
            response.headers[k] = v

    # overwrite content-length with current length
    response.headers["Content-Length"] = str(response.content_length)

    return response


def run_antivirus(res: Response):
    body = (
        bytes(f"Content-Type: {res.headers['Content-Type']}\r\n\r\n\r\n", "ascii")
        + res.content
    )
    msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(body)
    virus_found = 0

    for att in msg.iter_attachments():
        scan_res = clamav.instream(io.BytesIO(att.get_content()))["stream"]
        content_id = att["Content-ID"]
        if scan_res[0] == "OK":
            app.logger.info(f"scanned ${content_id} : ${scan_res}")
        else:
            app.logger.info(f"virus found ${content_id} : ${scan_res}")

            # replace document
            att.set_content(config["config"]["virus_found"])

            # fix headers
            del att["MIME-Version"]
            del att["Content-Transfer-Encoding"]
            att["Content-Transfer-Encoding"] = "binary"
            att["Content-ID"] = content_id

            virus_found += 1

    if virus_found:
        body = msg.as_bytes()

        # remove headers of envelope
        body = body[body.find(b"\n\n") + 2 :]

        return body


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=5001)
