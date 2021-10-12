import av_gate
import requests
from unittest import mock

def test_connector_sds(monkeypatch):
    "check endpoint is replaced"

    class MockResponse:
        content = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sd:ConnectorServices xmlns:pi="http://ws.gematik.de/int/version/ProductInformation/v1.1" xmlns:sd="http://ws.gematik.de/conn/ServiceDirectory/v3.1" xmlns:si="http://ws.gematik.de/conn/ServiceInformation/v2.0">
    <pi:ProductInformation>
        <pi:InformationDate>2021-10-07T13:41:01.421Z</pi:InformationDate>
        <pi:ProductTypeInformation>
            <pi:ProductType>Konnektor</pi:ProductType>
            <pi:ProductTypeVersion>4.4.0</pi:ProductTypeVersion>
        </pi:ProductTypeInformation>
        <pi:ProductIdentification>
            <pi:ProductVendorID>GMTK</pi:ProductVendorID>
            <pi:ProductCode>AKTORFM</pi:ProductCode>
            <pi:ProductVersion>
                <pi:Local>
                    <pi:HWVersion>1.27.0</pi:HWVersion>
                    <pi:FWVersion>1.27.0</pi:FWVersion>
                </pi:Local>
            </pi:ProductVersion>
        </pi:ProductIdentification>
        <pi:ProductMiscellaneous>
            <pi:ProductVendorName>Gematik</pi:ProductVendorName>
            <pi:ProductName>Aktor-FM</pi:ProductName>
        </pi:ProductMiscellaneous>
    </pi:ProductInformation>
    <sd:TLSMandatory>true</sd:TLSMandatory>
    <sd:ClientAutMandatory>true</sd:ClientAutMandatory>
    <si:ServiceInformation>
        <si:Service Name="CardTerminalService">
            <si:Abstract>CardTerminalService</si:Abstract>
            <si:Versions>
                <si:Version TargetNamespace="http://ws.gematik.de/conn/CardTerminalService/WSDL/v1.1" Version="1.1.0">
                    <si:Abstract>CardTerminalService</si:Abstract>
                    <si:EndpointTLS Location="https://kon-instanz1.titus.ti-dienste.de:443/soap-api/CardTerminalService/1.1.0"/>
                </si:Version>
            </si:Versions>
        </si:Service>
        <si:Service Name="EventService">
            <si:Abstract>EventService</si:Abstract>
            <si:Versions>
                <si:Version TargetNamespace="http://ws.gematik.de/conn/EventService/v7.2" Version="7.2.0">
                    <si:Abstract>EventService</si:Abstract>
                    <si:EndpointTLS Location="https://kon-instanz1.titus.ti-dienste.de:443/soap-api/EventService/7.2.0"/>
                </si:Version>
            </si:Versions>
        </si:Service>
        <si:Service Name="PHRManagementService">
            <si:Abstract>PHRManagementService</si:Abstract>
            <si:Versions>
                <si:Version TargetNamespace="http://ws.gematik.de/conn/phrs/PHRManagementService/WSDL/v1.3" Version="1.3.0">
                    <si:Abstract>PHRManagementService</si:Abstract>
                    <si:EndpointTLS Location="https://kon-instanz1.titus.ti-dienste.de:443/soap-api/PHRManagementService/1.3.0"/>
                </si:Version>
            </si:Versions>
        </si:Service>
        <si:Service Name="PHRService">
            <si:Abstract>PHRService</si:Abstract>
            <si:Versions>
                <si:Version TargetNamespace="http://ws.gematik.de/conn/phrs/PHRService/WSDL/v1.3" Version="1.3.0">
                    <si:Abstract>PHRService</si:Abstract>
                    <si:EndpointTLS Location="https://kon-instanz1.titus.ti-dienste.de:443/soap-api/PHRService/1.3.0"/>
                </si:Version>
            </si:Versions>
        </si:Service>
    </si:ServiceInformation>
</sd:ConnectorServices>"""

    def mock_request(*args, **kwargs):
        return MockResponse()

    monkeypatch.setattr(requests, "request", mock_request)


    with av_gate.app.test_request_context("/connector.sds"):
        with av_gate.app.test_client() as client:

            res = client.get("/connector.sds")
            data = res.data[:]

            assert b"https://kon-instanz1.titus.ti-dienste.de:443/soap-api/PHRManagementService/1.3.0" in data
            assert b"https://localhost/soap-api/PHRService/1.3.0" in data
