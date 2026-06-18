FROM node:20 AS build
WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM nginx:alpine

COPY --from=build /app/dist/Frontend/browser  /usr/share/nginx/html

# SPA fallback (optional)
# COPY nginx.conf /etc/nginx/conf.d/default.conf