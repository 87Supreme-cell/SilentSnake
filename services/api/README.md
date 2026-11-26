# api (Go)

`silentsnake-api` is the local REST API for the dashboard. It uses only the standard library `net/http`, listens on `127.0.0.1` only, requires a bearer token, validates input strictly and rate-limits requests. It runs the capture engine as a child process. Specification: [`docs/api/rest-api.md`](../../docs/api/rest-api.md).

```sh
scripts/dev.sh bash -c 'cd services && go build -trimpath -o /work/target/silentsnake-api ./api'
target/silentsnake-api --capture-bin target/release/silentsnake-capture --interface any
```

Not yet built: FIPS mode through GOFIPS140 toggled by config, which comes with the config file work.
