# Tasks

- [x] SOAP-Request für retrieveDocument auf Titus
- [x] Proxy Framework einrichten
- [x] Forward Routing für Requests
- [x] Response Filter
- [x] Response split multipart message
- [x] Logging für Multithreading
- [ ] Routing für Konnektoren (über DNS Alias statt Proxy)
- [ ] Einrichten auf Ubuntu (AV, nginx, python)
- [ ] TLS & Zertifikate

# Offene Fragen

- Ist der Client "Primärsystem" Proxy fähig? Lässt sich ein Proxy konfigurieren?

Falls ja, kann die Zieladresse des Konnektors unverändert bleiben und der AV-Proxy kann diese Zieladresse nutzen

- Welche Daten benötige ich, um den richtigen Konntektor zu addressieren?

In den Anfragen sind jeweils als Kontext angegeben - ich könnte mir vorstellen, dass diese Daten ausreichend sind:
```xml
<m0:Context>
  <m1:MandantId>Mandant1</m1:MandantId>
  <m1:ClientSystemId>ClientID1</m1:ClientSystemId>
  <m1:WorkplaceId>CATS</m1:WorkplaceId>
</m0:Context>
```

- Woher bekomme ich die Client-Zertifikate?

