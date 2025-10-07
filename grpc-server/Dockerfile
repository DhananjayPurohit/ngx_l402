# Build stage
FROM rust:1.75 as builder

WORKDIR /app

# Install protobuf compiler and other dependencies
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy the entire project
COPY . .

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bullseye-slim

# Install necessary runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder stage
COPY --from=builder /app/target/release/grpc-server /usr/local/bin/grpc-server

# Expose the gRPC port
EXPOSE 50051

# Run the gRPC server
CMD ["grpc-server"]
