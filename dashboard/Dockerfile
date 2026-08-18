# AEGIS v2 dashboard (React + Vite). Dev-server image for the demo.
FROM node:20-alpine

WORKDIR /app
COPY package.json ./
# Use npm install (no lockfile committed) so the image builds from package.json.
RUN npm install

COPY . .
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5173"]
