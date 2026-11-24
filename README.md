# MCP Gatekeeper

The front door for self-hosted MCP servers: people sign in with passkeys, connect ChatGPT and Claude as MCP
connectors through a built-in OAuth 2.1 authorization server, and the owner revokes access per person or per
connection.

Extracted from [Family Hub](docs/PLAN.md) and shared with [Homie](https://github.com/devXpro/homie).

- **Go** (`net/http`, `log/slog`): passkeys and sessions (`auth`), the OAuth server and consent (`oauth`), the
  access check in front of an MCP endpoint (`mcpguard`), accounts, people and invites (`people`), HTTP security
  (`httpsec`), the admin unix socket (`adminsock`), the SPA handler (`webui`), Cloudflare Tunnel setup
  (`tunnel/cloudflare`).
- **Storage:** interfaces in `store`, adapters for MongoDB (`store/mongostore`) and SQLite (`store/sqlitestore`),
  one conformance suite (`store/storetest`).
- **Admin UI:** a React package in `ui/`, consumed by a git tag.

Status: being extracted (step 1 of [docs/PLAN.md](docs/PLAN.md)).

## Development

```sh
make lint test          # Go lint and unit tests
make integration        # tests that need Docker (MongoDB)
make ui                 # the UI package: typecheck, lint, unit tests
```

## License

[MIT](LICENSE)
