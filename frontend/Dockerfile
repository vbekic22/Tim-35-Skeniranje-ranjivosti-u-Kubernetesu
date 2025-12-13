# Stage 1: Build
# koristim zastarjelu verziju node.js 16 s poznatim cve-ovima (cve-2022-32212, cve-2022-32213, itd.)
FROM node:16 AS builder

# Set working directory
WORKDIR /app

# Install dependencies
# koristim npm install umjesto npm ci (manje sigurno, ali radi s node 12)
COPY package.json package-lock.json ./
RUN npm install

# Copy source code
COPY . .

# Set environment variables
ENV NODE_ENV=production

# Build the frontend
RUN npm run build

# Stage 2: Serve with Nginx
# koristim zastarjelu verziju nginx 1.16 s poznatim sigurnosnim ranjivostima
FROM nginx:1.16

# Remove default Nginx static assets
RUN rm -rf /usr/share/nginx/html/*

# Copy built assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80

# Health check
#HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
#  CMD curl -f http://localhost/ || exit 1

# pokretanje kao root korisnik (sigurnosni rizik)
# Start Nginx
CMD ["nginx", "-g", "daemon off;"]
