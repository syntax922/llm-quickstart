# llm-quickstart

A tiny Go web app that renders the LM Studio gateway quickstart documentation and safely exposes the `_oauth2_proxy`
cookie value server-side (without client-side cookie access).

## Features
- Single `/quickstart` page with documentation-grade styling.
- Server-side cookie extraction (HttpOnly safe).
- Copy buttons for cookies and curl examples.
- Strict no-cache headers on every response.
- Assets embedded into the Go binary (no external dependencies).
- JSON helper endpoint at `/quickstart/api/session` for server-rendered session metadata.

## Local development

```bash
go run ./
```

Visit `http://localhost:8080/quickstart` and supply a `_oauth2_proxy` cookie via your browser or curl.

## Build

```bash
go build -o llm-quickstart ./
```

## Container image

```bash
docker build -t ghcr.io/syntax922/llm-quickstart:latest .
```

## Configuration

The service is intentionally static. Update `main.go` if you need to change:
- Base URL
- Cookie name
- OAuth audience
