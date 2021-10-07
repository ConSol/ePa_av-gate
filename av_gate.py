import email.parser
import email.policy
import io
import re

import clamd
import requests
from flask import Flask, Response, request

CLAMD_SOCKET = "/tmp/clamd.socket"
UPSTREAM_SERVER = "https://kon-instanz1.titus.ti-dienste.de" # "https://127.0.0.1:5000"
PROXY_SSL_CERT = "cert/ps_epa_consol_01.crt"
PROXY_SSL_KEY = "cert/ps_epa_consol_01.key"
SSL_VERIFY = True

VIRUS_MSG = "Das Dokument ist mit einem Virus infiziert und wird nicht übertragen."

cd = clamd.ClamdUnixSocket(path=CLAMD_SOCKET)
reg_retrieve_document = re.compile(b"RetrieveDocumentSetRequest")


app = Flask(__name__)

@app.route("/")
def hello():
    return "up and running 2"

@app.route("/<path:path>", methods=["POST"])
def soap(path):
    # get data from upstream
    upstream = requests.post(
        f"{UPSTREAM_SERVER}{request.path}",
        headers=request.headers,
        data=request.get_data(),
        cert=(PROXY_SSL_CERT, PROXY_SSL_KEY),
        verify=SSL_VERIFY,
    )

    if reg_retrieve_document.search(request.get_data()):
        response = Response(run_antivirus(upstream) or upstream.content)
    else:
        response = Response(upstream.content)

    # copy headers from upstream response
    for k, v in upstream.headers.items():
        if k not in ["Transfer-Encoding", "Content-Length"]:
            response.headers[k] = v

    response.headers["Content-Length"] = str(response.content_length)

    return response

def run_antivirus(res: Response):
    body = bytes(f"Content-Type: {res.headers['Content-Type']}\r\n\r\n\r\n", "ascii") + res.content
    msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(body)
    virus_found = 0

    for att in msg.iter_attachments():
        scan_res = cd.instream(io.BytesIO(att.get_content()))["stream"]
        content_id = att["Content-ID"]
        if scan_res[0] == "OK":
            app.logger.info(f"scanned ${content_id} : ${scan_res}")
        else:
            app.logger.info(f"virus found ${content_id} : ${scan_res}")

            # replace document
            att.set_content(VIRUS_MSG)

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
