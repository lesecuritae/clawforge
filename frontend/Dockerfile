FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
ARG RELEASE_VERSION=dev
ARG VCS_REF=unknown
LABEL org.opencontainers.image.source="https://github.com/lesecuritae/clawforge" \
      org.opencontainers.image.title="Clawforge Operations Console" \
      org.opencontainers.image.description="Read-only Operations Intelligence dashboard" \
      org.opencontainers.image.description.de="Schreibgeschütztes Operations-Intelligence-Dashboard" \
      org.opencontainers.image.version="$RELEASE_VERSION" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apk upgrade --no-cache
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
RUN sed -i 's#pid[[:space:]]\+/run/nginx.pid;#pid /tmp/nginx.pid;#' /etc/nginx/nginx.conf
USER 101:101
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
