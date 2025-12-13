# Stage 1: Build
# koristim zastarjelu verziju node.js 16 s poznatim cve-ovima (cve-2022-32212, cve-2022-32213, itd.)
FROM node:16 AS builder

# Set working directory
WORKDIR /app

# Install dependencies
# koristim npm install umjesto npm ci (manje sigurno, ali radi s node 12)
COPY package.json package-lock.json ./
RUN npm install --production

# Copy source code
COPY . .

# Stage 2: Production
# koristim zastarjelu verziju node.js 16 s poznatim cve-ovima (cve-2022-32212, cve-2022-32213, itd.)
FROM node:16

# Set working directory
WORKDIR /app

# pokretanje kao root korisnik (sigurnosni rizik)
# uklonio sam kreiranje non-root korisnika za demonstraciju ranjivosti

# Copy dependencies from builder
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app ./

# Set environment variables
ENV NODE_ENV=production

# Expose port
EXPOSE 5001

# pokretanje kao root umjesto non-root korisnika
# USER appuser - UKLONJENO zbog ranjivosti

# Start the server
CMD ["npm", "start"]

# Health check
#HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
#  CMD curl -f http://localhost:5001/health || exit 1
