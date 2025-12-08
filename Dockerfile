FROM nginx:1.28.0
EXPOSE 8000

# Install ca-certificates for SSL trust store management
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY target/release/libngx_l402_lib.so /etc/nginx/modules/libngx_l402_lib.so
COPY nginx.conf /etc/nginx/nginx.conf
COPY index.html /usr/share/nginx/html/protected/index.html
COPY index.html /usr/share/nginx/html/protected-timeout/index.html
COPY index.html /usr/share/nginx/html/tenant1/index.html
COPY index.html /usr/share/nginx/html/tenant2/index.html

# Create directory for shared CA certs
RUN mkdir -p /app/shared-certs

USER root

# Entrypoint script to add CA cert to trust store before starting nginx
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]