FROM golang as build
ENV GO111MODULE=on
ARG THREAGILE_VERSION=${THREAGILE_VERSION:-"test"}
ENV THREAGILE_VERSION=${THREAGILE_VERSION}
# https://stackoverflow.com/questions/36279253/go-compiled-binary-wont-run-in-an-alpine-docker-container-on-ubuntu-host
#ENV CGO_ENABLED=0 # cannot be set as otherwise plugins don't run
WORKDIR /app
COPY . /app
RUN make
FROM alpine

LABEL type="threagile"
LABEL org.opencontainers.image.authors="Christian Schneider <mail@christian-schneider.net>, Martin Vesterlund <Otyg@users.noreply.github.com>"
LABEL org.opencontainers.image.url="https://github.com/threagile/threagile, https://github.com/Otyg/threagile"
LABEL org.opencontainers.image.source="https://github.com/Otyg/threagile"
LABEL org.opencontainers.image.vendor="https://github.com/Otyg/"
LABEL org.opencontainers.image.licenses="MIT"
# add certificates
RUN apk add ca-certificates
# add graphviz, fonts
RUN apk add --update --no-cache graphviz ttf-freefont
# https://stackoverflow.com/questions/66963068/docker-alpine-executable-binary-not-found-even-if-in-path
RUN apk add libc6-compat
# https://stackoverflow.com/questions/34729748/installed-go-binary-not-found-in-path-on-alpine-linux-docker
# clean apk cache
RUN rm -rf /var/cache/apk/*

WORKDIR /app
COPY --from=build /app/threagile /app/threagile
COPY --from=build /app/*.so /app/
COPY --from=build /app/LICENSE.txt /app/LICENSE.txt
COPY --from=build /app/report/template/background.pdf /app/background.pdf
COPY --from=build /app/support/* /app/
COPY --from=build /app/server /app/server
COPY --from=build /app/demo/example/threagile.yaml /app/threagile-example-model.yaml
COPY --from=build /app/demo/stub/threagile.yaml /app/threagile-stub-model.yaml
RUN mkdir /data
RUN chown -R 1000:1000 /app /data
USER 1000:1000
ENV PATH=/app:$PATH
ENV GIN_MODE=release
ENTRYPOINT ["/app/threagile"]
CMD ["-help"]
