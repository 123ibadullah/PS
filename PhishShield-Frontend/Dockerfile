# Frontend multi-stage Dockerfile for PhishShield React + Vite app
# Stage 1: Builder
FROM node:20-alpine AS builder

WORKDIR /app

# Install pnpm
RUN npm install -g pnpm

# Copy workspace metadata
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./

# Copy project files
COPY . .

# Install dependencies
RUN pnpm install --frozen-lockfile

# Build the application
RUN pnpm --filter @workspace/phishshield build

# Stage 2: Runtime (Nginx)
FROM nginx:alpine

# Copy built files from builder to nginx
COPY --from=builder /app/artifacts/phishshield/dist /usr/share/nginx/html

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Expose ports
EXPOSE 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q -O- http://localhost/health || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
