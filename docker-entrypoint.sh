#!/bin/sh
set -e

# Add any CA certificates from the shared-certs directory to the trust store
if [ -d "/app/shared-certs" ]; then
    certs_found=$(ls /app/shared-certs/*.crt 2>/dev/null || true)
    if [ -n "$certs_found" ]; then
        echo "Adding custom CA certificates to trust store..."
        cp /app/shared-certs/*.crt /usr/local/share/ca-certificates/
        update-ca-certificates
        echo "CA certificates added successfully"
    else
        echo "No custom CA certificates found in /app/shared-certs"
    fi
else
    echo "Shared certs directory does not exist"
fi

# Execute the main command
exec "$@"
