FROM node:18-alpine

WORKDIR /app

# Install lnurl-node globally and openssl for self-signed cert generation
RUN apk add --no-cache openssl && npm install -g lnurl

# Create config and certs directory
RUN mkdir -p /app/config /app/certs /app/shared-certs

# Generate self-signed CA and server certificate for HTTPS
RUN openssl genrsa -out /app/certs/ca.key 4096 && \
    openssl req -x509 -new -nodes -key /app/certs/ca.key -sha256 -days 365 \
        -out /app/certs/ca.crt -subj "/C=US/ST=Test/L=Test/O=TestCA/CN=TestCA" && \
    openssl genrsa -out /app/certs/key.pem 4096 && \
    openssl req -new -key /app/certs/key.pem -out /app/certs/server.csr \
        -subj "/C=US/ST=Test/L=Test/O=Test/CN=lnurl-server" && \
    echo "subjectAltName=DNS:lnurl-server,DNS:localhost,IP:127.0.0.1" > /app/certs/extfile.cnf && \
    openssl x509 -req -in /app/certs/server.csr -CA /app/certs/ca.crt -CAkey /app/certs/ca.key \
        -CAcreateserial -out /app/certs/cert.pem -days 365 -sha256 -extfile /app/certs/extfile.cnf

# Default environment variables
ENV PORT=3000
ENV LND_HOSTNAME=lndnode-receiver:10010
ENV LND_CERT_PATH=/root/.lnd/tls.cert
ENV LND_MACAROON_PATH=/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon

EXPOSE 3000

# Start lnurl server with LND backend and HTTPS
# Also copy CA cert to shared volume at startup
CMD ["sh", "-c", "cp /app/certs/ca.crt /app/shared-certs/ 2>/dev/null || true; until [ -f $LND_CERT_PATH ] && [ -f $LND_MACAROON_PATH ]; do echo 'Waiting for LND files...'; sleep 2; done; lnurl server --host 0.0.0.0 --port $PORT --protocol https --tls.certPath /app/certs/cert.pem --tls.keyPath /app/certs/key.pem --lightning.backend lnd --lightning.config.hostname $LND_HOSTNAME --lightning.config.cert $LND_CERT_PATH --lightning.config.macaroon $LND_MACAROON_PATH"]
