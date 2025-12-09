FROM nginx:1.28.0
EXPOSE 8000

COPY target/release/libngx_l402_lib.so /etc/nginx/modules/libngx_l402_lib.so
COPY nginx.conf /etc/nginx/nginx.conf
COPY index.html /usr/share/nginx/html/protected/index.html
COPY index.html /usr/share/nginx/html/protected-timeout/index.html
COPY index.html /usr/share/nginx/html/tenant1/index.html
COPY index.html /usr/share/nginx/html/tenant2/index.html

USER root

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
