# -- Stage 1: Build the Go application ----
FROM golang:1.21 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o sec-aws main.go

# ---- Stage 2: Build the Python server ----
FROM python:3.11 AS python-server

WORKDIR /server

COPY server /server

RUN pip install --no-cache-dir -r requirements.txt

# ---- Stage 3: Create the final runtime image ----
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/sec-aws /app/sec-aws

COPY --from=python-server /server /server

RUN chmod +x /app/sec-aws

EXPOSE 8000 8080

# run both services
CMD ["/bin/sh", "-c", "/app/sec-aws & python /server/main.py"]
