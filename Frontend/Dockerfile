
FROM node:20 AS build
WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build -- --configuration production

FROM nginx:alpine

COPY --from=build /app/dist/Frontend/browser /usr/share/nginx/html

EXPOSE 80
