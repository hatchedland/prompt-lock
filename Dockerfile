FROM golang:1.24-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /promptlock-server ./cmd/promptlock-server/

FROM alpine:3.20

RUN apk add --no-cache ca-certificates
COPY --from=builder /promptlock-server /promptlock-server

EXPOSE 8080

ENTRYPOINT ["/promptlock-server"]
CMD ["--http-port", "8080", "--level", "balanced", "--redact-pii"]
