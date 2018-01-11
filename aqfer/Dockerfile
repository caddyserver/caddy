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

RUN curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.32.0/install.sh | bash
RUN nvm install 4.8.4
RUN npm install amazon-dax-client

# additional modules currently imported in caddy/caddymain/run.go
RUN mkdir -p /go/src/github.com/fellou89
ADD ./aqfer/caddy-awscloudwatch /go/src/github.com/fellou89/caddy-awscloudwatch
ADD ./aqfer/caddy-reauth /go/src/github.com/fellou89/caddy-reauth
ADD ./aqfer/caddy-secrets /go/src/github.com/fellou89/caddy-secrets
ADD ./aqfer/caddy-awsdynamodb /go/src/github.com/fellou89/caddy-awsdynamodb
ADD ./aqfer/caddy-redis /go/src/github.com/fellou89/caddy-redis

# adds caddy source under caddy directory on container
RUN go get github.com/caddyserver/builds
RUN mkdir -p /go/src/github.com/mholt/caddy
ADD ./ /go/src/github.com/mholt/caddy

# builds caddy binary and moves to location of Caddyfile
WORKDIR /go/src/github.com/mholt/caddy/caddy
RUN go run build.go; mv caddy /
ADD ./aqfer/Caddyfile /Caddyfile

WORKDIR /
# Using golang-auth mini service until we have an actual auth endpoint
ADD ./aqfer/golang-auth /golang-auth
CMD cd /golang-auth/main; go run main.go & cd /; ./caddy
