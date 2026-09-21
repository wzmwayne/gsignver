# syntax=docker/dockerfile:1
# 交叉编译阶段：在构建机上按目标架构编译，无需 QEMU。
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
      go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/gsignver ./cmd/gsignver \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
      go build -trimpath -ldflags "-s -w" -o /out/gsigtest ./cmd/gsigtest

# 运行阶段：scratch，无 shell、无 libc 依赖，非 root。
FROM scratch
COPY --from=build /out/gsignver /gsignver
COPY --from=build /out/gsigtest /gsigtest

# 运行身份可按目标机的数据卷属主调整：
#   docker build --build-arg APP_UID=1000 --build-arg APP_GID=1000 .
# scratch 里没有 chown，数据卷属主必须与此一致，否则容器无法写入 /data。
ARG APP_UID=65534
ARG APP_GID=65534
USER $APP_UID:$APP_GID
ENV GSIGNVER_ADDR=:8080 \
    GSIGNVER_DATA=/data \
    GOMEMLIMIT=48MiB \
    GOGC=50
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/gsigtest", "-health", "-url", "http://127.0.0.1:8080"]
ENTRYPOINT ["/gsignver"]
CMD ["serve"]
