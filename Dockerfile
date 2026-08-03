# Dockerfile para LogDiagnostix Enterprise Dashboard
FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
