

Beispiel Testumgebung mit Docker bzw. Podman


Bauen der Images
````
podman build -t avgate .
podman build -t c-icap -f c-icap/Dockerfile
```

Start des ICAP-Servers
```
podman run --name c-icap -d -p 1344:1344 c-icap
```

Start des Konnektor Mocks

```
flask --app avgate.konnektor_mock:app run --cert=adhoc
```

Start des AV-Gateways als Container

```
podman run --name avgate -p 8443:443 \
  -e ICAP_HOST=host.containers.internal \
  -e ICAP_SERVICE=icap://egal/avscan \
  -e KONNEKTOR=https://host.containers.internal:5000 \
  -v ./cert:/app/cert \
  --rm avgate
```

`host.containers.internal` ist der dns name des hosting hosts.

Der Mount kann alternative auch mit bind beschrieben werden, funktioniert aber nicht auf macos:

... `--mount type=bind,source="$(pwd)"/cert,target=/app/cert,readonly`

Test cURLs

```
# Konnektor-Mock direkt
curl --cert cert/kclient.cert --key cert/kclient.key --insecure https://localhost:5000/connector.sds

# Test Verbindung icap
curl --cert cert/kclient.cert --key cert/kclient.key --insecure https://localhost:8443/health

# Test Verbindung Konnektor
curl --cert cert/kclient.cert --key cert/kclient.key --insecure https://localhost:8443/check

# Connector.sds - URLs zu den Services sollten ersetzt sein
curl --cert cert/kclient.cert --key cert/kclient.key --insecure https://localhost:8443/connector.sds

# Document Download - schadhafte Anlagen werden ersetzt
curl --cert cert/kclient.cert --key cert/kclient.key --insecure https://localhost:8443/soap-api/PHRService/1.3.0 -H "Content-Type: text/xml" --data-binary "@script/retriveDocumentSet.xml" --output - | less

# Direkte Anfrage an Konnektor mit schadhaften Anlagen
curl --cert cert/kclient.cert --key cert/kclient.key --insecure https://localhost:5000/soap-api/PHRService/1.3.0 -H "Content-Type: text/xml" --data-binary "@script/retriveDocumentSet.xml" --output - | less
```

Der Mock reagiert nur auf die Anfragen /connector.sds und /soap-api/PHRService/1.3.0.