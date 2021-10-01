from flask import Flask, make_response
import io

app = Flask(__name__)

@app.route("/")
def root():
  return "up and running"

@app.route("/soap-api")
def soap():
  fn = open("./samples/retrievedocument-resp.xop", "br")
  data = io.BytesIO(fn.read())
  response = make_response(data)
  response.headers.set('Content-Type', 'application/xop+xml; type="application/soap+xml"')
  response.headers.set('Content-Transfer-Encoding', 'binary')
  return response

if __name__ == '__main__':
    app.run(host="::", port=5000, debug=True)
