FROM ubuntu:18.04
RUN apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y c-icap libicapapi-dev clamav curl less vim libc-icap-mod-virus-scan && \
    usermod -a -G c-icap c-icap && \
    mkdir -p /var/run/c-icap && \
    touch /var/run/c-icap/c-icap.id && \
    chown -R c-icap:c-icap /var/run/c-icap && \
    /usr/bin/freshclam && \
    chown -R c-icap:c-icap /etc/c-icap/ && \
    echo "acl all src 0.0.0.0/0.0.0.0" >> /etc/c-icap/c-icap.conf && \
    echo "icap_access allow all" >> /etc/c-icap/c-icap.conf && \
    echo "Include /etc/c-icap/virus_scan.conf" >> /etc/c-icap/c-icap.conf && \
    sed -i 's/^StartServers.*/StartServers 1/' /etc/c-icap/c-icap.conf && \
    sed -i 's/^MaxServers.*/StartServers 1/' /etc/c-icap/c-icap.conf && \
    sed -i 's/^Service echo srv/#Service echo srv/' /etc/c-icap/c-icap.conf && \
    sed -i 's/^Group c-icap/Group nogroup/' /etc/c-icap/c-icap.conf && \
    # add DebugLevel for details on c-icap
    # sed -i 's/^DebugLevel.*/DebugLevel 8/' /etc/c-icap/c-icap.conf
    # remove Allow204As200okZeroEncaps when use 200 instead of 204
    echo "Allow204As200okZeroEncaps on" >> /etc/c-icap/c-icap.conf && \
    echo "Include clamav_mod.conf" >> /etc/c-icap/virus_scan.conf

ADD ./entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
USER c-icap
EXPOSE 1344
ENTRYPOINT ["/entrypoint.sh"]