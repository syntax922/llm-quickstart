FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY . ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o /out/llm-quickstart ./

FROM gcr.io/distroless/static:nonroot

WORKDIR /
COPY --from=builder /out/llm-quickstart /llm-quickstart

EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/llm-quickstart"]
