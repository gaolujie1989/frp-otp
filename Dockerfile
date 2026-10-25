FROM golang:1.27.3-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/frp-otp .

FROM scratch
COPY --from=builder /out/frp-otp /frp-otp
USER 65532:65532
EXPOSE 9000
ENTRYPOINT ["/frp-otp"]
CMD ["-e", "web", "-c", "/etc/frp-otp.json"]
