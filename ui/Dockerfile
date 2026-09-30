FROM nginx:1.31-alpine
COPY locations.conf /etc/nginx/mcpwarden/locations.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY static/ /usr/share/nginx/html/
EXPOSE 80 443
