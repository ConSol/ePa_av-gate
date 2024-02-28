import io

from flask import Flask, abort, send_file

app = Flask(__name__)


@app.route("/")
def root():
    return "up and running"


@app.route("/ws/PHRService/1.3.0", methods=["POST", "GET"])
def soap():
    fn = open("./samples/retrievedocument-resp_eicar", "br")
    b = io.BytesIO(fn.read().replace(b"\n", b"\r\n"))

    response = send_file(
        b,
        mimetype="application/xop+xml; type='application/soap+xml'",
        as_attachment=False,
    )
    apply_headers(response)

    return response


@app.route("/connector.sds")
def connector_sds():
    fn = open("./samples/connector.sds", "br")
    b = io.BytesIO(fn.read().replace(b"\n", b"\r\n"))

    response = send_file(
        b,
        mimetype="application/xop+xml; type='application/soap+xml'",
        as_attachment=False,
    )
    apply_headers(response)

    return response


@app.route("/ws/SignatureService", methods=["POST", "GET"])
def signature_service():
    abort(500, "will not work")


def apply_headers(response):
    response.headers.set("Content-Transfer-Encoding", "binary")
    response.headers.set("X-Content-Type-Options", "nosniff")
    response.headers.set("X-XSS-Protection", "1; mode=block")
    response.headers.set(
        "Cache-Control", "no-cache, no-store, max-age=0, must-revalidate"
    )
    response.headers.set("Pragma", "no-cache")
    response.headers.set("Expires", "0")
    response.headers.set(
        "Strict-Transport-Security", "max-age=31536000 ; includeSubDomains"
    )
    response.headers.set("X-Frame-Options", "DENY")
    response.headers.set(
        "Content-Type",
        'multipart/related; type="application/xop+xml"; boundary="uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b"; start="<root.message@cxf.apache.org>"; start-info="application/soap+xml"',
    )


if __name__ == "__main__":
    app.run(port=5002, debug=True, ssl_context="adhoc")
