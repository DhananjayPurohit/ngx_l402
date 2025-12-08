#!/bin/bash
set -e

# Add any CA certificates from the shared-certs directory to the trust store
if [ -d "/app/shared-certs" ] && [ "$(ls -A /app/shared-certs/*.crt 2>/dev/null)" ]; then
    echo "Adding custom CA certificates to trust store..."
    cp /app/shared-certs/*.crt /usr/local/share/ca-certificates/
    update-ca-certificates
    echo "CA certificates added successfully"
else
    echo "No custom CA certificates found in /app/shared-certs"
fi

# Execute the main command
exec "$@"
