FROM scratch

VOLUME /certs
VOLUME /www
EXPOSE 6121

ADD main /main

CMD ["/main", "-bind=0.0.0.0", "-certpath=/certs/", "-www=/www"]
