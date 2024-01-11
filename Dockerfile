FROM nginx:latest

# Timezone is needed for installing uwsgi
ENV TZ=Europe/Berlin
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get -y update \
&& apt-get -y install net-tools nginx supervisor gettext-base uwsgi uwsgi-plugin-python3 python3 python3-pip

COPY requirements.txt log_conf.yaml /app/
RUN pip3 install -r /app/requirements.txt --break-system-packages

COPY avgate/avgate.py /app/avgate/
COPY avgate/replacements/ /app/avgate/replacements/
COPY cert/ /app/cert/
COPY docker/ /app/

RUN chmod u+x /app/startup.sh
ENTRYPOINT ["/app/startup.sh"]

EXPOSE 443
