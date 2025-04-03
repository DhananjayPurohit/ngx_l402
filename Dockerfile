FROM nginx:1.27.3
EXPOSE 8000
COPY target/release/libngx_l402_lib.so /etc/nginx/modules/libngx_l402_lib.so
COPY nginx.conf /etc/nginx/nginx.conf
COPY index.html /usr/share/nginx/html/protected/index.html
USER root
RUN mkdir -p /var/lib/nginx && chmod 777 /var/lib/nginx
CMD ["nginx", "-g", "daemon off;"]