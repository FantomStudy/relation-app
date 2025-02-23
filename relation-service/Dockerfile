#build stage

FROM golang:alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o relation-service main.go

#final stage
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/relation-service .

EXPOSE 3001

CMD ["./relation-service"]