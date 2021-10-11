from unittest import mock
import argparse

from proxy.http.parser import HttpParser, httpParserTypes
from app_plugin.message_av import MessageAVPlugin, VIRUS_MSG

chunks = [
    b"""HTTP/1.0 200 OK
Content-Type: multipart/related; type="application/xop+xml"; boundary="uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b"; start="<root.message@cxf.apache.org>"; start-info="application/soap+xml"
Content-Length: 3807

--uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b
Content-Type: application/xop+xml; charset=UTF-8; type="application/soap+xml"
Content-Transfer-Encoding: binary
Content-ID: <root.message@cxf.apache.org>

<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Header><Action xmlns="http://www.w3.org/2005/08/addressing">urn:ihe:iti:2007:RetrieveDocumentSetResponse</Action><MessageID xmlns="http://www.w3.org/2005/08/addressing">urn:uuid:24a151ef-19ca-414e-890a-b0f9f0397f10</MessageID><To xmlns="http://www.w3.org/2005/08/addressing">http://www.w3.org/2005/08/addressing/anonymous</To><RelatesTo xmlns="http://www.w3.org/2005/08/addressing">ec50fa1f-ff62-49d3-a870-f5218afba633</RelatesTo></soap:Header><soap:Body><ns5:RetrieveDocumentSetResponse xmlns="http://ws.gematik.de/conn/ConnectorCommon/v5.0" xmlns:ns2="http://ws.gematik.de/conn/ConnectorContext/v2.0" xmlns:ns3="http://ws.gematik.de/fa/phr/v1.1" xmlns:ns4="http://ws.gematik.de/conn/phrs/PHRService/v1.3" xmlns:ns5="urn:ihe:iti:xds-b:2007" xmlns:ns6="urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0" xmlns:ns7="urn:oasis:names:tc:ebxml-regrep:xsd:rs:3.0" xmlns:ns8="urn:oasis:names:tc:ebxml-regrep:xsd:cms:3.0" xmlns:ns9="urn:oasis:names:tc:ebxml-regrep:xsd:query:3.0" xmlns:ns10="urn:oasis:names:tc:ebxml-regrep:xsd:lcm:3.0" xmlns:ns11="urn:oasis:names:tc:dss:1.0:core:schema" xmlns:ns12="http://www.w3.org/2000/09/xmldsig#" xmlns:ns13="http://ws.gematik.de/tel/error/v2.0" xmlns:ns14="urn:hl7-org:v3" xmlns:ns15="urn:oasis:names:tc:SAML:1.0:assertion" xmlns:ns16="http://ws.gematik.de/fa/vsdm/vsd/v5.2" xmlns:ns17="http://www.w3.org/2006/05/addressing/wsdl" xmlns:ns18="urn:ihe:iti:rmd:2017"><ns7:RegistryResponse status="urn:oasis:names:tc:ebxml-regrep:ResponseStatusType:Success"/><ns5:DocumentResponse><ns5:HomeCommunityId>urn:oid:1.2.276.0.76.3.1.91.1</ns5:HomeCommunityId><ns5:RepositoryUniqueId>1.2.276.0.76.3.1.91.1</ns5:RepositoryUniqueId><ns5:DocumentUniqueId>2.25.140094387439901233557</ns5:DocumentUniqueId><ns5:mimeType>application/pdf</ns5:mimeType><ns5:Document><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="cid:06487236-1327-4b51-a129-756d5df95533-233@urn%3Aihe%3Aiti%3Axds-b%3A2007"/></ns5:Document></ns5:DocumentResponse><ns5:DocumentResponse><ns5:HomeCommunityId>urn:oid:1.2.276.0.76.3.1.91.1</ns5:HomeCommunityId><ns5:RepositoryUniqueId>1.2.276.0.76.3.1.91.1</ns5:RepositoryUniqueId><ns5:DocumentUniqueId>2.25.83711722020886177921</ns5:DocumentUniqueId><ns5:mimeType>application/xml</ns5:mimeType><ns5:Document><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="cid:06487236-1327-4b51-a129-756d5df95533-234@urn%3Aihe%3Aiti%3Axds-b%3A2007"/></ns5:Document></ns5:DocumentResponse><ns5:DocumentResponse><ns5:HomeCommunityId>urn:oid:1.2.276.0.76.3.1.91.1</ns5:HomeCommunityId><ns5:RepositoryUniqueId>1.2.276.0.76.3.1.91.1</ns5:RepositoryUniqueId><ns5:DocumentUniqueId>2.25.102925591037611682627</ns5:DocumentUniqueId><ns5:mimeType>application/pdf</ns5:mimeType><ns5:Document><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="cid:06487236-1327-4b51-a129-756d5df95533-235@urn%3Aihe%3Aiti%3Axds-b%3A2007"/></ns5:Document></ns5:DocumentResponse></ns5:RetrieveDocumentSetResponse></soap:Body></soap:Envelope>

""".replace(b'\n', b'\r\n'),
    b"""
--uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b
Content-Type: application/octet-stream
Content-Transfer-Encoding: binary
Content-ID: <06487236-1327-4b51-a129-756d5df95533-233@urn:ihe:iti:xds-b:2007>

this is a document

--uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b
Content-Type: application/octet-stream
Content-Transfer-Encoding: binary
Content-ID: <06487236-1327-4b51-a129-756d5df95533-234@urn:ihe:iti:xds-b:2007>

X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

--uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b--

""".replace(b'\n', b'\r\n'),
]

flags = argparse.Namespace(log_level="DEBUG", log_format="")


def test_check_response():
    "check infected message has been replaced"
    client = mock.Mock()
    request = HttpParser(httpParserTypes.REQUEST_PARSER)
    request.body = memoryview(b"... RetrieveDocumentSetRequest ...")
    cut = MessageAVPlugin(uid=None, flags=flags, client=client, event_queue=None)
    cut.handle_client_request(request)
    cut.handle_upstream_chunk(memoryview(chunks[0]))
    cut.handle_upstream_chunk(memoryview(chunks[1]))

    assert b'infiziert' in cut.response.body
    assert b'06487236-1327-4b51-a129-756d5df95533-234@urn:ihe:iti:xds-b:2007' in cut.response.body
    assert b'06487236-1327-4b51-a129-756d5df95533-233@urn:ihe:iti:xds-b:2007' in cut.response.body
    assert client.queue.called == True

def test_pass_response():
    "check passing request on different actions"
    client = mock.Mock()
    request = HttpParser(httpParserTypes.REQUEST_PARSER)
    request.body = memoryview(b"... whatever ...")
    cut = MessageAVPlugin(uid=None, flags=flags, client=client, event_queue=None)
    cut.handle_client_request(request)
    cut.handle_upstream_chunk(memoryview(chunks[0]))
    cut.handle_upstream_chunk(memoryview(chunks[1]))

    assert client.queue.called == False
