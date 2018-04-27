FROM aqfer-build:latest

# VIM ONLY USED FOR DEVELOPMENT OF CADDY STACK
# RUN apt-get update
# RUN apt-get -y install vim

WORKDIR /
CMD ./caddy
