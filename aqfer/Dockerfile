FROM golang:1.9

# NODE ONLY NEEDED WHILE DAX IS RUN AS NODE SERVER
# ENV NVM_DIR /root/.nvm
# ENV NODE_VERSION 8.5.0

# use bash instead of sh so nvm can be sourced
# RUN rm /bin/sh && ln -s /bin/bash /bin/sh
# RUN curl -o- https://raw.githubusercontent.com/creationix/nvm/v0.32.0/install.sh | bash; . $NVM_DIR/nvm.sh; nvm install $NODE_VERSION; nvm use $NODE_VERSION

# ENV NODE_PATH $NVM_DIR/versions/node/v$NODE_VERSION/lib/node_modules
# ENV PATH $NVM_DIR/versions/node/v$NODE_VERSION/bin:$PATH

# VIM ONLY USED FOR DEVELOPMENT OF CADDY STACK
# RUN apt-get update
# RUN apt-get -y install vim

RUN go get gopkg.in/yaml.v2
RUN go get github.com/aws/aws-sdk-go/aws
RUN go get github.com/aws/aws-sdk-go/aws/awserr
RUN go get github.com/aws/aws-sdk-go/aws/session
RUN go get github.com/aws/aws-sdk-go/service/cloudwatchlogs
RUN go get github.com/garyburd/redigo/redis
RUN go get github.com/dgrijalva/jwt-go
RUN go get github.com/pkg/errors
RUN go get github.com/sirupsen/logrus
RUN go get github.com/satori/go.uuid
RUN go get github.com/pquerna/cachecontrol/cacheobject
RUN go get github.com/lucas-clemente/quic-go
RUN go get github.com/stretchr/testify/require

# additional modules currently imported in caddy/caddymain/run.go
RUN go get github.com/fellou89/caddy-cache
RUN go get github.com/fellou89/caddy-reauth
RUN go get github.com/startsmartlabs/caddy-secrets
RUN go get github.com/startsmartlabs/caddy-awscloudwatch
RUN go get github.com/startsmartlabs/caddy-transformresponse
RUN go get github.com/startsmartlabs/caddy-transformrequest
RUN go get github.com/startsmartlabs/caddy-redis
# ADD ./aqfer/redis /go/src/github.com/startsmartlabs/caddy-redis

# adds caddy source under caddy directory on container
RUN go get github.com/caddyserver/builds
RUN mkdir -p /go/src/github.com/mholt/caddy
ADD ./ /go/src/github.com/mholt/caddy

ADD ./aqfer/Caddyfile /Caddyfile
ADD ./aqfer/.secrets.yml /.secrets.yml
ADD ./aqfer/test.go /test.go
ADD ./aqfer/scripts/run_unit_tests.sh /run_unit_tests.sh
ADD ./aqfer/integration_tests/ /aqfer/integration_tests/
ADD ./aqfer/scripts/run_integration_tests.sh /run_integration_tests.sh
ADD ./aqfer/scripts/run_sanity_tests.sh /run_sanity_tests.sh
RUN mkdir /temp_cache

# builds caddy binary and moves to location of Caddyfile
WORKDIR /go/src/github.com/mholt/caddy/caddy
RUN go run build.go; mv caddy /

WORKDIR /
CMD ./caddy & go run test.go
