#!/bin/sh

export KONNEKTOR_HOST=$(echo $KONNEKTOR | cut -d'/' -f3 | cut -d':' -f1)

envsubst '${ICAP_HOST} ${ICAP_SERVICE} ${KONNEKTOR} ${SSL_VERIFY} ${ICAP_HOST} ${ICAP_SERVICE} ${LOG_LEVEL}' < /app/template/avgate.ini > /app/avgate.ini
envsubst '${KONNEKTOR} ${KONNEKTOR_HOST} ${SSL_VERIFY_CLIENT}' < /app/template/nginx.conf > /app/nginx.conf

# if you prefer certs via env vars
# echo ${KCLIENT_CERT} > /app/cert/kclient.cert
# echo ${KCLIENT_KEY} > /app/cert/kclient.key
# echo ${CA_CERT} > /app/cert/ca-cert.pem
# echo ${SERVER_CERT} > /app/cert/server.cert
# echo ${SERVER_KEY} > /app/cert/server.key

supervisord -c /app/supervisord.conf
