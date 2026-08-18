# AEGIS v2 dashboard (React + Vite). Dev-server image for the demo.
FROM node:20-alpine

WORKDIR /app
COPY package.json package-lock.json ./
# npm ci installs exactly the pinned tree from package-lock.json, so the image
# matches local installs and cannot silently drift to newer transitive deps.
RUN npm ci

COPY . .
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"]
