FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath \
    -ldflags="-s -w -X main.buildVersion=$VERSION -X main.buildRev=$REVISION -X main.buildDate=$CREATED" \
    -o /out/frp-otp .

FROM scratch
COPY --from=builder /out/frp-otp /frp-otp
USER 65532:65532
EXPOSE 9000
ENTRYPOINT ["/frp-otp"]
CMD ["-e", "web", "-c", "/etc/frp-otp.json"]
