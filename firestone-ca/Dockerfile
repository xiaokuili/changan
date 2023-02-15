FROM golang:1.16.2 as builder
ENV GOPROXY=https://goproxy.cn,direct
ENV GONOSUMDB=chainmaker.org
COPY . /chainmaker-ca
RUN cd /chainmaker-ca/src && go build -o chainmaker-ca

FROM centos:7.6.1810
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

RUN mkdir -p /usr/local/lib64/pkcs11
ENV LD_LIBRARY_PATH=/usr/local/lib64/pkcs11

COPY --from=builder /chainmaker-ca/src/chainmaker-ca /chainmaker-ca/chainmaker-ca
WORKDIR /chainmaker-ca
VOLUME [ "/log" ,"/crypto-config" ,"/chainmaker-ca/conf"]
