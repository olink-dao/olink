# Build Geth in a stock Go builder container
FROM golang:1.15-alpine as builder

RUN apk add --no-cache make gcc musl-dev linux-headers git

ADD . /go-olink
RUN cd /go-olink && make geth

# Pull Geth into a second stage deploy alpine container
FROM alpine:latest

RUN apk add --no-cache ca-certificates
COPY --from=builder /go-olink/build/bin/geth /usr/local/bin/

EXPOSE 8545 8546 30303 30303/udp
ENTRYPOINT ["geth"]
