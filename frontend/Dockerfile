# PhishGuard UI: built once with Vite, then served as static files by nginx.
# Usually started via docker-compose.yml in the repository root.

# --- Stage 1: build the static files -------------------------------------------
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# The backend URL is baked into the JavaScript at build time (Vite reads VITE_*).
# It is the address the BROWSER uses, so localhost:8000 is right for local Docker.
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

# --- Stage 2: serve them ---------------------------------------------------------
FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
