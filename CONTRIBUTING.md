# Contributing

## Issues

File bugs and feature requests via [GitHub Issues](https://github.com/KrakoX/capsule/issues).

For security vulnerabilities, follow the [Security Policy](SECURITY.md) instead.

## Pull Requests

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Ensure `make lint` and `make test` pass locally
4. Use [conventional commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `refactor:`, `docs:`, `test:`
5. Open a PR against `main`

## Local development

```bash
# Build
make build

# Run tests
make test

# Run linter (requires golangci-lint)
make lint

# Dry-run release build (requires goreleaser)
make release-dry
```

## Code style

- Format with `gofmt` (enforced by CI)
- All linter checks in `.golangci.yml` must pass
- No bare `print` statements — the tool writes to `os.Stdout` / `os.Stderr` explicitly
