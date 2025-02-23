#build stage
FROM golang:alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o notification-service main.go

#final stage
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/notification-service .

EXPOSE 5000

CMD ["./notification-service"]