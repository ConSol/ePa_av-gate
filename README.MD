# AV-Proxy

Proxy für den Gematik Konnektor zum AV-Scan von herungergeladener Dokumente.

- [SOAP Schnittstelle](docs/soap.md)
- [Infrastruktur](docs/infrastruktur.md)
- [Tasks & offene Fragen](docs/tasks.md)

## Installation

### ClamAV

`clamd` soll als Deamon laufen und die DB initialisiert sein.

Folgende Einstellung werden benötigt:
```
LocalSocket /tmp/clamd.socket
```

Der Pfad für den Socket ist in `av_gate.py` anzupassen.

### Python

Die benötigte Version ist 3.8. oder später

Folgende Dateien werden benötigt:
```
av_gate.py
requirements.txt
wsgi.py
cert/*
```

Installation der benötigten Libs mit

`pip3 install -r requirements.txt` - oder mit `pip`, wenn pip3 nicht verfügbar.

Innerhalb der av_gate.py sind die Konfigurationen anzupassen
```
CLAMD_SOCKET = "/tmp/clamd.socket"
UPSTREAM_SERVER = "https://kon-instanz1.titus.ti-dienste.de" # "https://127.0.0.1:5000"
PROXY_SSL_CERT = "cert/ps_epa_consol_01.crt"
PROXY_SSL_KEY = "cert/ps_epa_consol_01.key"
SSL_VERIFY = True
```

### uWSGI

Hab ich noch nicht für Ubuntu gemacht, daher hier der Verweis:

https://uwsgi-docs.readthedocs.io/en/latest/Install.html

### NGINX

Ein Muster für die config-Datei liegt bei. Die URLs, Ports und Zertifikate sind noch anzupassen.

Aktuell fungiert NGINX ausschließlich als Proxy für die Verbindungen vom Client (Primäranwendung) zum AV-Gate. Die Verbindung zum Konnektor erfolgt bis jetzt ausschließlich durch das AV-Gate.

## Architektur

TBD

