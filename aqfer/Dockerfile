FROM golang:1.8

RUN go get github.com/aws/aws-sdk-go/aws
RUN go get github.com/aws/aws-sdk-go/aws/awserr
RUN go get github.com/aws/aws-sdk-go/aws/session
RUN go get github.com/aws/aws-sdk-go/service/cloudwatchlogs
RUN go get github.com/aws/aws-sdk-go/service/dynamodb
RUN go get github.com/garyburd/redigo/redis
RUN go get github.com/nicolasazrak/caddy-cache 
RUN go get github.com/nicolasazrak/caddy-cache/storage
RUN go get github.com/BTBurke/caddy-jwt
RUN go get github.com/pkg/errors
RUN go get github.com/sirupsen/logrus
RUN go get github.com/satori/go.uuid
RUN go get gopkg.in/yaml.v2

RUN mkdir -p /go/src/github.com/fellou89
ADD ./aqfer/caddy-awscloudwatch /go/src/github.com/fellou89/caddy-awscloudwatch
ADD ./aqfer/caddy-reauth /go/src/github.com/fellou89/caddy-reauth
ADD ./aqfer/caddy-secrets /go/src/github.com/fellou89/caddy-secrets
ADD ./aqfer/caddy-awsdynamodb /go/src/github.com/fellou89/caddy-awsdynamodb
ADD ./aqfer/caddy-redis /go/src/github.com/fellou89/caddy-redis

RUN go get github.com/caddyserver/builds
RUN mkdir -p /go/src/github.com/mholt/caddy
ADD ./ /go/src/github.com/mholt/caddy

WORKDIR /go/src/github.com/mholt/caddy/caddy
RUN go run build.go; mv caddy /

WORKDIR /
ADD ./aqfer/Caddyfile /Caddyfile

# Using golang-auth mini service until we have an actual auth endpoint
ADD ./aqfer/golang-auth /golang-auth
CMD cd /golang-auth/main; go run main.go & cd /; ./caddy
