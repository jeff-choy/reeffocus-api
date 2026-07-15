# Deployable to anything that takes a container (Fly.io, Railway, Render, Cloud Run).
FROM node:22-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
# only runtime deps — tsx/typescript stay out of the image
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
# hosts inject PORT; the server reads it and falls back to 4000
EXPOSE 4000
CMD ["node", "dist/index.js"]
