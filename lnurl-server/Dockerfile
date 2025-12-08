FROM node:18-alpine

WORKDIR /app

# Install lnurl-node globally
RUN npm install -g lnurl

# Create config directory
RUN mkdir -p /app/config

# Default environment variables
ENV PORT=3000
ENV LND_HOSTNAME=lndnode-receiver:10010
ENV LND_CERT_PATH=/root/.lnd/tls.cert
ENV LND_MACAROON_PATH=/root/.lnd/data/chain/bitcoin/regtest/admin.macaroon

EXPOSE 3000

# Start lnurl server with LND backend
CMD ["sh", "-c", "until [ -f $LND_CERT_PATH ] && [ -f $LND_MACAROON_PATH ]; do echo 'Waiting for LND files...'; sleep 2; done; lnurl server --host 0.0.0.0 --port $PORT --lightning.backend lnd --lightning.config.hostname $LND_HOSTNAME --lightning.config.cert $LND_CERT_PATH --lightning.config.macaroon $LND_MACAROON_PATH"]
