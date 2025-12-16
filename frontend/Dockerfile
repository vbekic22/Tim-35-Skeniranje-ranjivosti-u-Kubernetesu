# Stage 1: Build
FROM node:20 AS builder

# Set working directory
WORKDIR /app

#install dependencies
COPY package.json package-lock.json ./
RUN npm install

# Copy source code
COPY . .

# Set environment variables
ENV NODE_ENV=production

# Build the frontend
RUN npm run build

# Stage 2: Serve with nginx
FROM nginx:1.27

# Remove default Nginx static assets
RUN rm -rf /usr/share/nginx/html/*

# Copy built assets from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom Nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Expose port 80
EXPOSE 80

# Start Nginx server
CMD ["nginx", "-g", "daemon off;"]
