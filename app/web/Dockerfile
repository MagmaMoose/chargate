# ---- build stage ----
FROM node:20-alpine AS build
WORKDIR /app

# VITE_API_BASE is baked into the static bundle at build time. Override with
#   docker build --build-arg VITE_API_BASE=https://api.example.com .
ARG VITE_API_BASE=http://localhost:8000
ENV VITE_API_BASE=$VITE_API_BASE

COPY package.json package-lock.json* ./
RUN npm ci || npm install

COPY . .
RUN npm run build

# ---- serve stage ----
FROM nginx:1.27-alpine AS serve
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
