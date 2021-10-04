import logging
import email
from urllib import parse as urlparse
from typing import Any, Optional

from proxy.http.proxy import HttpProxyBasePlugin
from proxy.http.parser import HttpParser, HttpParserStates, HttpParserTypes
from proxy.http.methods import httpMethods

logger = logging.getLogger(__name__)

class MessageAVPlugin(HttpProxyBasePlugin):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Create a new http protocol parser for response payloads
        self.response = HttpParser(HttpParserTypes.RESPONSE_PARSER)
        self.chunks = []

    def before_upstream_connection(
            self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_client_request(
            self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        self.chunks.append(chunk)
        self.response.parse(chunk.tobytes())
        print(f"state ${self.response.state}")
        # If response is complete, modify and dispatch to client
        if self.response.state == 6: # HttpParserStates.COMPLETE
            self.read_response()
            self.client.queue(memoryview(self.response.build_response()))
        return memoryview(b'')

    def on_upstream_connection_close(self) -> None:
        pass

    def read_response(self):
        if not self.response.has_header(b'content-type'):
            return
        pass


