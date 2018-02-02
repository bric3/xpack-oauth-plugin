FROM docker.elastic.co/elasticsearch/elasticsearch:5.4.0

COPY build/distributions/x-pack-oauth-realm-0.5-xpack_5.4.0.zip .

RUN /usr/share/elasticsearch/bin/x-pack/extension \
       install \
       file:///usr/share/elasticsearch/x-pack-oauth-realm-0.5-xpack_5.4.0.zip \
    && rm x-pack-oauth-realm-0.5-xpack_5.4.0.zip

#ENTRYPOINT ["/bin/ls", "-alh"]
#CMD ["/bin/ls", "-alh"]
