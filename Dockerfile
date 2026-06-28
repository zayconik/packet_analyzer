FROM node:20-bookworm AS builder

WORKDIR /app

# Install C++ build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake && \
    rm -rf /var/lib/apt/lists/*

# Copy root package.json (for reference)
COPY package.json ./

# Copy C++ source
COPY CMakeLists.txt ./
COPY src/ ./src/
COPY include/ ./include/

# Build dpi_api binary
RUN mkdir -p build && cd build && cmake .. && make dpi_api && \
    cp dpi_api /app/dpi_api

# Install server dependencies
COPY server/package*.json ./server/
RUN cd server && npm ci --production

# Copy server source
COPY server/ ./server/

# Create runtime directories
RUN mkdir -p server/uploads server/outputs

FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache libstdc++

COPY --from=builder /app/dpi_api ./
COPY --from=builder /app/server ./server
COPY --from=builder /app/package.json ./

ENV NODE_ENV=production
EXPOSE 5000

CMD ["node", "server/index.js"]
