#!/bin/bash

envsubst '${ICAP_HOST} ${ICAP_SERVICE} ${KONNEKTOR}' < /app/template/avgate.ini > /app/avgate.ini
envsubst '${KONNEKTOR}' < /app/template/nginx.conf > /app/nginx.conf
supervisord -c /app/supervisord.conf
