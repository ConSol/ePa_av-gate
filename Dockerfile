FROM nginx:1.25

# check server cert from konnektor
ENV SSL_VERIFY true
# check client cert for incomming connections
ENV SSL_VERIFY_CLIENT on

# icap server - only hostname
ENV ICAP_HOST host.containers.internal
# icap service name - default works with c-icap
ENV ICAP_SERVICE icap://any/avscan
# one of DEBUG INFO WARNING ERROR CRITICAL
ENV LOG_LEVEL INFO

# Timezone is needed for installing uwsgi
ENV TZ=Europe/Berlin

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get -y update \
&& apt-get -y install net-tools nginx supervisor gettext-base uwsgi uwsgi-plugin-python3 python3 python3-pip

COPY requirements.txt wsgi.py /app/
RUN pip3 install -r /app/requirements.txt --break-system-packages

COPY avgate/avgate.py /app/avgate/
COPY avgate/replacements/ /app/avgate/replacements/
COPY docker/ /app/

RUN chmod u+x /app/startup.sh
ENTRYPOINT ["/app/startup.sh"]

EXPOSE 443
