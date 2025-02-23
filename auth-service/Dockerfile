#build stage

FROM golang:alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o auth-service main.go


#final stage
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/auth-service .

COPY uploads/avatars/default.jpg /app/uploads/avatars/default.jpg

RUN mkdir -p /app/uploads/avatars

EXPOSE 3000

CMD ["./auth-service"]