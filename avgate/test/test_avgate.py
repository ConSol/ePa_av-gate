import re
from unittest import mock
import xml.etree.ElementTree as ET
from unittest.mock import Mock

from avgate import avgate
import pytest
import requests

avgate.config.read_dict(
    {
        "config": {
            "remove_malicious": "true",
            "icap_host": "127.0.0.1"
        },
        "*:400": {"konnektor": "some"},
        "8.8.8.8:401": {"konnektor": "some", "proxy_all_services": "true"},
    }
)

avgate.scan_file = avgate.get_file_scanner()

@pytest.fixture
def client(monkeypatch):
    avgate.config.update({"*:400": {"Konnektor": "https://nowhere.com"}})

    with avgate.app.test_client() as client:
        with avgate.app.app_context():

            # Mock Requests
            headers = {
                "Content-Type": 'multipart/related; type="application/xop+xml"; '
                'boundary="uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b"; '
                'start="<root.message@cxf.apache.org>"; '
                'start-info="application/soap+xml";charset=UTF-8'
            }

            class MockResponse:
                headers = {"Test-Header": "bla"}
                content = b"""bla bla"""
                status_code = 200
                raw = mock.Mock()
                raw.headers = {"bla": "foo"}

                def __init__(self, **kwargs):
                    self.__dict__.update(kwargs)

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc_val, exc_tb):
                    pass

            def mock_request(url: str, data: bytes, *args, **kwargs):

                if url.endswith("connector.sds"):
                    return MockResponse(
                        content=open("samples/connector.sds", "rb")
                        .read()
                        .replace(b"\n", b"\r\n")
                    )

                if b"GET_EICAR_MIME" in data:
                    return MockResponse(
                        headers=headers,
                        content=open("samples/retrievedocument-resp_eicar", "rb")
                        .read()
                        .replace(b"\n", b"\r\n")
                        .replace(
                            b"<ns5:mimeType>application/pdf</ns5:mimeType>",
                            b"<ns5:mimeType>application/xml</ns5:mimeType>",
                        ),
                    )

                if b"GET_EICAR" in data:
                    return MockResponse(
                        headers=headers,
                        content=open("samples/retrievedocument-resp_eicar", "rb")
                        .read()
                        .replace(b"\n", b"\r\n"),
                    )

                if b"ALL_EICAR" in data:
                    return MockResponse(
                        headers=headers,
                        content=open("samples/retrievedocument-resp_all_eicar", "rb")
                        .read()
                        .replace(b"\n", b"\r\n"),
                    )

                if b"ZIP_EICAR" in data:
                    return MockResponse(
                        headers=headers,
                        content=open("samples/retrievedocument-resp_eicar_zip", "rb")
                        .read()
                        .replace(b"\n--", b"\r\n--")
                        .replace(b"\nContent", b"\r\nContent")
                        .replace(b"\n\n", b"\r\n\r\n"),
                    )

                if b"RetrieveDocumentSet" in data:
                    return MockResponse(
                        headers=headers,
                        content=open("samples/retrievedocument-resp", "rb").read(),
                    )

                return MockResponse()

            monkeypatch.setattr(requests, "request", mock_request)
        
            yield client


@pytest.fixture
def antivir(monkeypatch):
    "Mock antivir"
    def mock_antivir(data: bytes):
        if b"EICAR" in data:
            return ("FOUND", "Win.Test.EICAR_HDB-1")
        else:
            return ("OK", None)

    monkeypatch.setattr(avgate, "scan_file", Mock(side_effect=mock_antivir))
        
@pytest.mark.parametrize(
    "real_ip,host,expected",
    [
        ("2.2.2.2", "7.7.7.7:400", 200),
        ("8.8.8.8", "7.7.7.7:400", 200),
        ("8.8.8.8", "7.7.7.7:401", 200),
        ("8.8.8.8", "7.7.7.7:402", 503),
    ],
)
def test_routing_ip(client, real_ip, host, expected):
    "check config pick by ip and port"

    res = client.get(
        "/connector.sds",
        headers={"X-real-ip": real_ip, "Host": host},
    )

    assert res.status_code == expected


def test_connector_sds(client):
    "check endpoint is replaced"

    res = client.get(
        "/connector.sds",
        headers={"X-real-ip": "9.9.9.9", "Host": "7.7.7.7:400"},
    )
    xml = ET.fromstring(res.text)

    assert (
        xml.find(
            "{*}ServiceInformation/{*}Service[@Name='PHRManagementService']/{*}Versions/{*}Version[@Version='1.3.0']/{*}EndpointTLS"
        ).attrib["Location"]
        == "https://kon-instanz1.titus.ti-dienste.de:443/soap-api/PHRManagementService/1.3.0"
    )
    assert (
        xml.find(
            "{*}ServiceInformation/{*}Service[@Name='PHRManagementService']/{*}Versions/{*}Version[@Version='2.0']/{*}EndpointTLS"
        ).attrib["Location"]
        == "https://kon-instanz1.titus.ti-dienste.de:443/soap-api/PHRManagementService/2.0"
    )
    assert (
        xml.find(
            "{*}ServiceInformation/{*}Service[@Name='PHRService']/{*}Versions/{*}Version[@Version='1.3.0']/{*}EndpointTLS"
        ).attrib["Location"]
        == "https://7.7.7.7:400/soap-api/PHRService/1.3.0"
    )
    assert (
        xml.find(
            "{*}ServiceInformation/{*}Service[@Name='PHRService']/{*}Versions/{*}Version[@Version='2.0']/{*}EndpointTLS"
        ).attrib["Location"]
        == "https://7.7.7.7:400/soap-api/PHRService/2.0"
    )
    assert (
        xml.find(
            "{*}ServiceInformation/{*}Service[@Name='PHRManagementService']/{*}Versions/{*}Version[@Version='1.3.0']/{*}EndpointTLS"
        ).attrib["Location"]
        == "https://kon-instanz1.titus.ti-dienste.de:443/soap-api/PHRManagementService/1.3.0"
    )


def test_proxy_all_service(client):
    "check all endpoints are replaced"

    res = client.get(
        "/connector.sds", headers={"X-real-ip": "8.8.8.8", "Host": "7.7.7.7:401"}
    )
    xml = ET.fromstring(res.data)
    data = (
        e.attrib["Location"]
        for e in xml.findall(
            "{*}ServiceInformation/{*}Service/{*}Versions/{*}Version/{*}EndpointTLS"
        )
    )

    assert any([x.startswith("https://7.7.7.7:401/soap-api/") for x in data])


def test_clam_av(client, antivir):
    "check clam_av is called"

    res = client.post(
        "https://7.7.7.7:400/soap-api/PHRService/1.3.0",
        headers={"X-real-ip": "9.9.9.9", "Host": "7.7.7.7:400"},
        data=open("avgate/test/retrieveDocumentSet_req.xml", "rb").read(),
    )

    parts = res.data.split(b"--uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b")
    assert len(parts) == 6  # n+2
    
    xml = ET.fromstring(parts[1][re.search(b"(\r\n){2}", parts[1]).end() :])
    assert avgate.scan_file.has_been_called()


def test_virus_removed(client, antivir):
    "check virus is removed"

    avgate.REMOVE_MALICIOUS = True

    data = (
        open("avgate/test/retrieveDocumentSet_req.xml", "rb")
        .read()
        .replace(b"\n", b"\r\n")
        .replace(
            b"<DocumentUniqueId>2.25.140094387439901233557</DocumentUniqueId>",
            b"<DocumentUniqueId>GET_EICAR</DocumentUniqueId>",
        )
    )

    res = client.post(
        "/soap-api/PHRService/1.3.0",
        headers={"X-real-ip": "9.9.9.9", "Host": "7.7.7.7:400"},
        data=data,
    )

    parts = res.data.split(b"--uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b")
    assert len(parts) == 5  # n+2

    xml = ET.fromstring(parts[1][re.search(b"(\r\n){2}?", parts[1]).end() :])
    assert avgate.scan_file.has_been_called()
    rres = xml.find("*//{*}RetrieveDocumentSetResponse/{*}RegistryResponse")
    assert (
        rres is not None
        and rres.attrib["status"]
        == "urn:ihe:iti:2007:ResponseStatusType:PartialSuccess"
    )
    assert (
        "detected as malware" in rres.find("*/{*}RegistryError").attrib["codeContext"]
    )


def test_virus_replaced(client, antivir):
    "check virus is removed"

    avgate.REMOVE_MALICIOUS = False

    data = (
        open("avgate/test/retrieveDocumentSet_req.xml", "rb")
        .read()
        .replace(b"\n", b"\r\n")
        .replace(
            b"<DocumentUniqueId>2.25.140094387439901233557</DocumentUniqueId>",
            b"<DocumentUniqueId>GET_EICAR</DocumentUniqueId>",
        )
    )

    res = client.post(
        "/soap-api/PHRService/1.3.0",
        headers={"X-real-ip": "9.9.9.9", "Host": "7.7.7.7:400"},
        data=data,
    )

    parts = res.data.split(b"--uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b")
    xml = ET.fromstring(parts[1].split(b"\r\n\r\n")[1])

    assert len(parts) == 6  # n+2
    assert avgate.scan_file.has_been_called()
    rres = xml.find("*//{*}RetrieveDocumentSetResponse/{*}RegistryResponse")
    assert (
        rres is not None
        and rres.attrib["status"]
        == "urn:oasis:names:tc:ebxml-regrep:ResponseStatusType:Success"
    )
    assert b"potentiell schadhafter Code" in parts[3]
    assert b'<?xml version="1.0" encoding="UTF-8"?>' in parts[3]


def test_virus_replaced_mimetypee(client, antivir):
    "check virus is replaced with same mimetype"

    avgate.REMOVE_MALICIOUS = False

    data = (
        open("avgate/test/retrieveDocumentSet_req.xml", "rb")
        .read()
        .replace(b"\n", b"\r\n")
        .replace(
            b"<DocumentUniqueId>2.25.140094387439901233557</DocumentUniqueId>",
            b"<DocumentUniqueId>GET_EICAR_MIME</DocumentUniqueId>",
        )
    )

    res = client.post(
        "/soap-api/PHRService/1.3.0",
        headers={"X-real-ip": "9.9.9.9", "Host": "7.7.7.7:400"},
        data=data,
    )

    parts = res.data.split(b"--uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b")
    xml = ET.fromstring(parts[1].split(b"\r\n\r\n")[1])

    assert len(parts) == 6  # n+2
    assert avgate.scan_file.has_been_called()
    rres = xml.find("*//{*}RetrieveDocumentSetResponse/{*}RegistryResponse")
    assert (
        rres is not None
        and rres.attrib["status"]
        == "urn:oasis:names:tc:ebxml-regrep:ResponseStatusType:Success"
    )
    assert b"potentiell schadhafter Code" in parts[3]


def test_virus_replaced_zip(client):
    "check virus is replaced on real zip - needs antivir running"

    avgate.REMOVE_MALICIOUS = False

    data = (
        open("avgate/test/retrieveDocumentSet_req.xml", "rb")
        .read()
        .replace(b"\n", b"\r\n")
        .replace(
            b"<DocumentUniqueId>2.25.140094387439901233557</DocumentUniqueId>",
            b"<DocumentUniqueId>ZIP_EICAR</DocumentUniqueId>",
        )
    )

    res = client.post(
        "/soap-api/PHRService/1.3.0",
        headers={"X-real-ip": "9.9.9.9", "Host": "7.7.7.7:400"},
        data=data,
    )

    parts = res.data.split(b"--uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b")
    assert len(parts) == 6  # n+2

    xml = ET.fromstring(parts[1].split(b"\r\n\r\n")[1])
    rres = xml.find("*//{*}RetrieveDocumentSetResponse/{*}RegistryResponse")
    assert (
        rres is not None
        and rres.attrib["status"]
        == "urn:oasis:names:tc:ebxml-regrep:ResponseStatusType:Success"
    )
    assert b"potentiell schadhafter Code" in parts[3]


def test_all_is_virusd(client, antivir):
    "check different error message if all msg are malicious"

    avgate.REMOVE_MALICIOUS = True

    data = (
        open("avgate/test/retrieveDocumentSet_req.xml", "rb")
        .read()
        .replace(b"\n", b"\r\n")
        .replace(
            b"<DocumentUniqueId>2.25.140094387439901233557</DocumentUniqueId>",
            b"<DocumentUniqueId>ALL_EICAR</DocumentUniqueId>",
        )
    )

    res = client.post(
        "/soap-api/PHRService/1.3.0",
        headers={"X-real-ip": "9.9.9.9", "Host": "7.7.7.7:400"},
        data=data,
    )

    parts = res.data.split(b"--uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b")
    xml = ET.fromstring(parts[1].split(b"\r\n\r\n")[1])

    assert len(parts) == 3  # n+2
    rres = xml.find("*//{*}RetrieveDocumentSetResponse/{*}RegistryResponse")
    assert (
        rres is not None
        and rres.attrib["status"]
        == "urn:oasis:names:tc:ebxml-regrep:ResponseStatusType:Failure"
    )
    assert (
        rres is not None
        and rres.find("*/{*}RegistryError[@errorCode='XDSRegistryMetadataError']")
        is not None
    )


def test_handle_multipart_request(client, antivir):
    "check handling of requests with multipart"

    data = b"""
Content-Type: multipart/related; type="application/xop+xml"; boundary="uuid:999"; start="<root.message@cxf.apache.org>"; start-info="application/soap+xml";charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive


--uuid:999
Content-Type: application/xop+xml; charset=UTF-8; type="application/soap+xml"
Content-Transfer-Encoding: binary
Content-ID: <root.message@cxf.apache.org>

""" + open(
        "avgate/test/retrieveDocumentSet_req.xml", "rb"
    ).read().replace(
        b"\n", b"\r\n"
    )

    res = client.post(
        "/soap-api/PHRService/1.3.0",
        headers={"X-real-ip": "9.9.9.9", "Host": "7.7.7.7:400"},
        data=data,
    )

    assert res.status_code == 200


@pytest.mark.parametrize(
    "in_id,out_id",
    [
        ("<345-345-345>", "345-345-345"),
        ("cid:345-345-345", "345-345-345"),
        ("<345-345-345@sdf>", "345-345-345"),
        ("cid:345-345-345", "345-345-345"),
        ("345-345-345%40sdf", "345-345-345"),
    ],
)
def test_extract_id(in_id, out_id):
    assert avgate.extract_id(in_id) == out_id
