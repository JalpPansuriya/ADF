# Multi-stage: build the Vite bundle, then serve the static output with nginx.
FROM node:22-alpine AS build

WORKDIR /app

COPY package.json ./
# No package-lock.json is committed (the dependency set is small and pinned to
# exact versions in package.json), so `npm install` is correct here rather than
# `npm ci`, which requires a lockfile.
RUN npm install

COPY . ./

# Vite inlines env vars at build time, so the API URL must be present now, not at
# container start. Passed through from docker-compose.
ARG VITE_ADF_API_URL=http://localhost:8000
ENV VITE_ADF_API_URL=$VITE_ADF_API_URL

RUN npm run build

FROM nginx:1.27-alpine AS serve

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -q --spider http://localhost/ || exit 1
