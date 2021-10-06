import logging
from urllib import parse as urlparse
from typing import Any, Optional

from proxy.http.proxy import HttpProxyBasePlugin
from proxy.http.parser import HttpParser

UPSTREAM_SERVER = b"http://localhost:1080"

logger = logging.getLogger(__name__)

class ProxyPassPlugin(HttpProxyBasePlugin):
    """Modifies client request to redirect all incoming requests to a fixed server address."""


    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        # set logger for process
        logging.basicConfig(level=self.flags.log_level, format=self.flags.log_format)

    def before_upstream_connection(self, request: HttpParser) -> Optional[HttpParser]:
        request.set_url(UPSTREAM_SERVER + request.url.path)
        return request

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass
