#!/usr/bin/env bash

DOMAIN="caddy.local"

# Add wildcard
WILDCARD="*.$DOMAIN"

# Set our CSR variables
SUBJ="
C=US
ST=NY
O=Local Developement
localityName=Local Developement
commonName=$WILDCARD
organizationalUnitName=Local Developement
emailAddress=admin@caddy.local
"

# Generate our Private Key, CSR and Certificate
openssl genrsa -out "$DOMAIN.key" 2048
openssl req -new -subj "$(echo -n "$SUBJ" | tr "\n" "/")" -key "$DOMAIN.key" -out "$DOMAIN.csr"
openssl x509 -req -days 3650 -in "$DOMAIN.csr" -signkey "$DOMAIN.key" -out "$DOMAIN.crt"
rm "$DOMAIN.csr"
