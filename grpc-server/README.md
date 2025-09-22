# Rust gRPC Server

A complete gRPC server implementation in Rust that serves content via Docker.

## Features

- **Generic Content Service**: Serves any content via gRPC
- **Protected Content**: Simulates L402-protected content
- **Free Content**: Serves freely accessible content
- **Docker Ready**: Complete containerization setup

## Quick Start

### 1. Build and Run with Docker Compose
```bash
cd grpc-server
docker-compose up --build
```

### 2. Test the Server

#### Using grpcurl (recommended):
```bash
# Install grpcurl
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# Test free content
grpcurl -plaintext localhost:50051 content.ContentService/GetFreeContent

# Test protected content
grpcurl -plaintext localhost:50051 content.ContentService/GetProtectedContent

# Test generic content
grpcurl -plaintext -d '{"path": "/test"}' localhost:50051 content.ContentService/GetContent
```

#### Using evans (interactive):
```bash
# Install evans
go install github.com/ktr0731/evans/cmd/evans@latest

# Connect to server
evans -r repl -p 50051 -h localhost
```

## API Endpoints

- `GetContent(path)` - Generic content for any path
- `GetProtectedContent()` - L402-protected content
- `GetFreeContent()` - Freely accessible content

## Docker Commands

```bash
# Build image
docker build -t grpc-content-server .

# Run container
docker run -p 50051:50051 grpc-content-server

# View logs
docker logs grpc-content-server
```

## Port

The server runs on port **50051** (standard gRPC port).
