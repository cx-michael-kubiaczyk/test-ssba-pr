# syntax=docker/dockerfile:1
FROM golang:alpine
# this is not a golang app actually so all of this will fail. It's just to generate KICS/IAC results
RUN mkdir -p /opt/ssba
WORKDIR /opt/ssba
copy src /opt/SAST2Cx1/src

RUN go build -v -o /opt/ssba .

EXPOSE 80
CMD ["./ssba"]
