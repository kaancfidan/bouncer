FROM golang:1.18 AS builder
ARG VERSION
WORKDIR /go/src/github.com/kaancfidan/bouncer
COPY . .
RUN go get -d -v
RUN sed -i "s/0.0.0-VERSION/"$VERSION"/" main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w"

FROM scratch
COPY --from=builder /go/src/github.com/kaancfidan/bouncer/bouncer bouncer
ENTRYPOINT ["./bouncer"]
