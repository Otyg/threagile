FROM alpine/git as clone
WORKDIR /app
RUN git clone https://github.com/Otyg/threagile-rules.git
COPY . /app/threagile


FROM golang as build
ENV GO111MODULE=on
WORKDIR /app
COPY . /app
COPY --from=clone /app/threagile-rules/risks /app/custom
RUN chmod +x build-threagile.sh && ./build-threagile.sh
FROM alpine

LABEL type="threagile"
LABEL org.opencontainers.image.authors="Christian Schneider <mail@christian-schneider.net>, Martin Vesterlund <Otyg@users.noreply.github.com>"
LABEL org.opencontainers.image.url="https://github.com/Threagile/threagile, https://github.com/Otyg/threagile"
LABEL org.opencontainers.image.source="https://github.com/Otyg/threagile"
LABEL org.opencontainers.image.vendor="https://github.com/Otyg/"
LABEL org.opencontainers.image.licenses="MIT"
RUN apk add --update --no-cache graphviz ttf-freefont && apk add ca-certificates && apk add curl && rm -rf /var/cache/apk/*
RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
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
ENTRYPOINT ["/app/threagile", "-custom-risk-rules-plugins", "accidental-logging-of-sensitive-data-rule.so,missing-monitoring-rule.so,missing-audit-of-sensitive-asset-rule.so,credential-stored-outside-of-vault-rule.so,insecure-handling-of-sensitive-data-rule.so,running-as-privileged-user.so"]
CMD ["-help"]
