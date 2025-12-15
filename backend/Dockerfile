FROM node:20 AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm install --production

COPY . .

FROM node:20

WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app ./

ENV NODE_ENV=production

EXPOSE 5001

CMD ["npm", "start"]