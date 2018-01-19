FROM golang:1.8


# NODE ONLY NEEDED WHILE DAX IS RUN AS NODE SERVER
ENV NVM_DIR /root/.nvm
ENV NODE_VERSION 8.5.0

# use bash instead of sh so nvm can be sourced
RUN rm /bin/sh && ln -s /bin/bash /bin/sh
RUN curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.32.0/install.sh | bash; . $NVM_DIR/nvm.sh; nvm install $NODE_VERSION; nvm use $NODE_VERSION

ENV NODE_PATH $NVM_DIR/versions/node/v$NODE_VERSION/lib/node_modules
ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH


# VIM ONLY USED FOR DEVELOPMENT OF CADDY STACK
RUN apt-get update
RUN apt-get -y install vim


RUN go get github.com/aws/aws-sdk-go/aws
RUN go get github.com/aws/aws-sdk-go/aws/awserr
RUN go get github.com/aws/aws-sdk-go/aws/session
RUN go get github.com/aws/aws-sdk-go/service/cloudwatchlogs
RUN go get github.com/aws/aws-sdk-go/service/dynamodb
RUN go get github.com/garyburd/redigo/redis
RUN go get github.com/BTBurke/caddy-jwt
RUN go get github.com/pkg/errors
RUN go get github.com/sirupsen/logrus
RUN go get github.com/satori/go.uuid
RUN go get gopkg.in/yaml.v2
RUN go get github.com/pquerna/cachecontrol/cacheobject

# additional modules currently imported in caddy/caddymain/run.go
RUN mkdir -p /go/src/github.com/fellou89
ADD ./aqfer/caddy-awscloudwatch /go/src/github.com/fellou89/caddy-awscloudwatch
ADD ./aqfer/caddy-secrets /go/src/github.com/fellou89/caddy-secrets
ADD ./aqfer/caddy-redis /go/src/github.com/fellou89/caddy-redis

ADD ./aqfer/caddy-awsdynamodb /go/src/github.com/fellou89/caddy-awsdynamodb 
RUN cd /go/src/github.com/fellou89/caddy-awsdynamodb; npm install amazon-dax-client

# adds caddy source under caddy directory on container
RUN go get github.com/caddyserver/builds
RUN mkdir -p /go/src/github.com/mholt/caddy
ADD ./ /go/src/github.com/mholt/caddy


ADD ./aqfer/caddy-cache /go/src/github.com/fellou89/caddy-cache
ADD ./aqfer/caddy-cache/storage /go/src/github.com/fellou89/caddy-cache/storage
ADD ./aqfer/caddy-reauth /go/src/github.com/fellou89/caddy-reauth


# builds caddy binary and moves to location of Caddyfile
WORKDIR /go/src/github.com/mholt/caddy/caddy
RUN go run build.go; mv caddy /

WORKDIR /

# Using golang-auth mini service until we have an actual auth endpoint
ADD ./aqfer/golang-auth /golang-auth

ADD ./aqfer/Caddyfile /Caddyfile
ADD ./aqfer/.secrets.yml /.secrets.yml
ADD ./aqfer/test.go /test.go
RUN mkdir /temp_cache
CMD cd /golang-auth/main; go run main.go & cd /; ./caddy & go run test.go
