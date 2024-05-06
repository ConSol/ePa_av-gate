#! /bin/bash
curl -v --location --request POST 'https://127.0.0.1:5000/ws/PHRService/1.3.0' \
--header 'Content-Type: application/xml' \
--insecure \
--cert cert/kclient1.cert --key cert/kclient1.key
--data-binary "@samples/retrievedocument-resp"
#--output - | less
