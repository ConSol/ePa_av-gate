import logging
import email.parser
import email.policy
import clamd
import io
import re
from typing import Any, Optional

from proxy.http.proxy import HttpProxyBasePlugin
from proxy.http.parser import HttpParser, httpParserStates, httpParserTypes

VIRUS_MSG = "Das Dokument ist mit einem Virus infiziert und wird nicht übertragen."

logger = logging.getLogger(__name__)

cd = clamd.ClamdUnixSocket(path="/tmp/clamd.socket")
reg_retrieve_document = re.compile(b"RetrieveDocumentSetRequest")


class MessageAVPlugin(HttpProxyBasePlugin):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        # Create a new http protocol parser for response payloads
        self.response = HttpParser(httpParserTypes.RESPONSE_PARSER)
        self.retrieve_document = False

        # set logger for process
        logging.basicConfig(level=self.flags.log_level, format=self.flags.log_format)

    def before_upstream_connection(self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        if request.method != b'CONNECT':
            self.retrieve_document = reg_retrieve_document.search(request.body) != None
        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        if chunk.tobytes().startswith(b"HTTP/1.1 100 Continue"):
            return chunk

        if self.retrieve_document:
            self.response.parse(chunk.tobytes())
            # If response is complete, modify and dispatch to client
            if self.response.state == httpParserStates.COMPLETE:
                self.check_response()
                self.client.queue(memoryview(self.response.build_response()))
            return memoryview(b"")

        else:
            return chunk

    def on_upstream_connection_close(self) -> None:
        pass

    def check_response(self):
        if not self.response.body:
            return

        b = self.response.build_response()
        # Remove http status first line
        b = b[b.find(b"\r\n") + 2 :]
        msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(b)
        virus_found = 0

        for att in msg.iter_attachments():
            scan_res = cd.instream(io.BytesIO(att.get_content()))["stream"]
            content_id = att["Content-ID"]
            if scan_res[0] == "OK":
                logger.info(f"scanned ${content_id} : ${scan_res}")
            else:
                logger.info(f"virus found ${content_id} : ${scan_res}")

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
            self.response.body = body

            # readjust content-length
            self.response.add_header(
                b"content-length", bytes(str(len(body) - 1), "ascii")
            )
