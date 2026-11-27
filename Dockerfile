FROM golang:1.26.11-bookworm@sha256:ea47ee45f1284d60f9cc09cb2c3bb4f508c256b640bd8bb30342ff13d1adcb52 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN go build -trimpath -ldflags="-s -w" -o /chezhi-license .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /chezhi-license /chezhi-license
USER 65532:65532
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=3 CMD ["/chezhi-license", "health-probe"]
ENTRYPOINT ["/chezhi-license"]
