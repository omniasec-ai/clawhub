# Use the official Bun image
FROM oven/bun:latest as builder

WORKDIR /app

# Copy package files
COPY package.json bun.lock ./
COPY packages ./packages

# Install dependencies
RUN bun install --frozen-lockfile

# Copy the rest of the source code
COPY . .

# Build the application
# This generates the .output directory via Nitro/TanStack Start
RUN bun run build

# Production stage
FROM oven/bun:latest as runner

WORKDIR /app

# Copy only the necessary files from the builder
COPY --from=builder /app/.output ./.output

# Set environment variables
ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

# Start the application
CMD ["bun", ".output/server/index.mjs"]
