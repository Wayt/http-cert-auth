#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <cert_name>"
    exit 1
fi

CERT_NAME="$1"

## Generate .key
openssl genrsa -out $CERT_NAME.key 4096

## Generate .csr
openssl req -new -key $CERT_NAME.key -out $CERT_NAME.csr

## Self sign the csr
openssl x509 -req -days 99999 -in $CERT_NAME.csr -signkey $CERT_NAME.key -out $CERT_NAME.crt

