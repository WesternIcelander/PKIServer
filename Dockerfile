# PKIServer runtime image.
#
# The image packages the shaded jar built on the host (SiggiHTTP comes from the siggi.io
# Maven repository, which a container build can't reach without credentials):
#
#   mvn package
#   docker build -t pkiserver .
#
# The config file is read from /etc/pkiserver/config.json (mount it read-only) and the data
# directory lives in the /data volume. Arguments are appended to the command line, so admin
# commands work as `docker run … pkiserver list` (see deploy/README.md).
FROM eclipse-temurin:21-jre

RUN useradd --system --uid 10001 --user-group --home-dir /data --no-create-home pkiserver \
    && mkdir -p /data /etc/pkiserver \
    && chown pkiserver:pkiserver /data

COPY target/PKIServer-1.0-SNAPSHOT.jar /app/PKIServer.jar
COPY deploy/config.example.json /etc/pkiserver/config.json

USER pkiserver
# SiggiHTTP caches Cloudflare's address ranges in the working directory, so it must be writable.
WORKDIR /data
VOLUME /data
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/PKIServer.jar", "--config", "/etc/pkiserver/config.json"]
