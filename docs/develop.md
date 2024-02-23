
Für die lokale Entwicklung kann die App direkt gestartet werden und hört auf den Port 5001.

Für den Zugriff ohne Nginx ist ein Beispiel unter ./script/retrieveDocumentSet-local.sh .

Für den Zugriff mit Nginx muss dieser umkonfiguriert werden. In nginx.conf statt uwsgi die Zeilen für den Fallback konfigurieren

```
    proxy_set_header X-real-ip $remote_addr;
    proxy_set_header host $server_addr:$server_port;
    proxy_pass "http://127.0.0.1:5001";
```

Ein lokaler icap server kann gestartet werden über
```
    docker build -t c-icap c-icap
    docker run -p 1344:1344 --rm --name c-icap c-icap
```
