FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /promptlock-server ./cmd/promptlock-server/

FROM gcr.io/distroless/static-debian12

COPY --from=builder /promptlock-server /promptlock-server

EXPOSE 8080 50051

ENTRYPOINT ["/promptlock-server"]
CMD ["--http-port", "8080", "--grpc-port", "50051", "--level", "balanced"]
