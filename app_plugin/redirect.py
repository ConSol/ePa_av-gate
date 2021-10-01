import logging
from urllib import parse as urlparse
from typing import Optional

from proxy.http.proxy import HttpProxyBasePlugin
from proxy.http.parser import HttpParser
from proxy.http.methods import httpMethods

logger = logging.getLogger(__name__)

class RedirectPlugin(HttpProxyBasePlugin):
    """Modifies client request to redirect all incoming requests to a fixed server address."""

    UPSTREAM_SERVER = b'http://localhost:5000'

    def before_upstream_connection(
            self, request: HttpParser) -> Optional[HttpParser]:
        # Redirect all non-https requests to inbuilt WebServer.
        if request.method != httpMethods.CONNECT:
            request.set_url(self.UPSTREAM_SERVER)
            # Update Host header too, otherwise upstream can reject our request
            if request.has_header(b'Host'):
                request.del_header(b'Host')
            request.add_header(
                b'Host', urlparse.urlsplit(
                    self.UPSTREAM_SERVER).netloc)
        logger.info('request', request.headers)
        return request

    def handle_client_request(
            self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        print(1)
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass
