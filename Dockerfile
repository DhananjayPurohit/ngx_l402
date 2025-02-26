FROM nginx:latest
EXPOSE 8000
COPY target/release/libngx_l402_lib.so /etc/nginx/modules/libngx_l402_lib.so
COPY nginx.conf /etc/nginx/nginx.conf
COPY index.html /usr/share/nginx/html/protected/index.html
CMD ["nginx", "-g", "daemon off;"]