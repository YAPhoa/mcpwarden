# OAuth mode (ChatGPT)

In OAuth mode, mcpwarden acts as an OAuth resource server: an external identity provider signs users in and issues tokens, and mcpwarden validates them. This is how ChatGPT connects, since it reaches remote MCP servers using OAuth 2.1.

OAuth mode is about how clients sign in to mcpwarden, not how mcpwarden signs in to the servers behind it. It cannot be combined with [panel accounts](accounts-and-access.md). The owner vault needs panel accounts, so in OAuth mode users can add only personal connections without authentication; see [Upstreams](upstreams.md).

## Setup

1. Configure an external identity provider with authorization-code + PKCE, its discovery document, a ChatGPT-compatible OAuth client, and token introspection.
2. Copy [the OAuth example](../../examples/oauth-config.yaml) to `config.yaml` and set its public HTTPS `resource` and provider URLs.
3. Set `MCPWARDEN_INTROSPECTION_CLIENT_ID` and `MCPWARDEN_INTROSPECTION_CLIENT_SECRET` in the Compose environment.
4. Use a public HTTPS endpoint or [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) for ChatGPT; the default loopback Compose binding is only for local clients.

The provider must issue access tokens whose audience matches `oauth.resource`, with an expiration and the configured scopes. mcpwarden validates those values on each `/mcp` request and publishes `/.well-known/oauth-protected-resource` for discovery.

OpenAI's [MCP authentication guide](https://developers.openai.com/plugins/build/auth) describes provider discovery, PKCE, callback, audience, and refresh-token requirements.

## Scopes and the admin panel

- The admin API requires an access token for the same user with the `mcp:manage` scope.
- The MCP view also uses that scope to select admin tools; tokens with client scopes receive only client tools.
- The panel currently accepts that token in its access-token dialog; an interactive browser login flow is not yet included.
- The local operator token does not grant access to `/mcp` or `/api` in OAuth mode.
- The validated access-token `sub` identifies the user for both `/mcp` and `/api`.

A live ChatGPT connection needs an identity provider and ChatGPT app setup, so the repository tests use a mock provider.
