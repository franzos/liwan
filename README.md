<br/>

<div align="center">
    <h2>
        <img float="left" src="./web/public/favicon.svg" width="16px"/>
        <a href="https://liwan.dev">liwan.dev</a> - Easy & Privacy-First Web Analytics
    </h2>
    <div>

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/franzos/liwan/test.yaml?style=flat-square)
![GitHub Release](https://img.shields.io/github/v/release/franzos/liwan?style=flat-square)
[![Container](https://img.shields.io/badge/Container-ghcr.io%2Ffranzos%2Fliwan%3Alatest-blue?style=flat-square)](https://github.com/franzos/liwan/pkgs/container/liwan)

</div>

</div>

<div align="center">
<a href="https://demo.liwan.dev/p/liwan.dev"><img width="45%" src="./data/images/liwan-desktop-dark.png" /></a>&nbsp;&nbsp;&nbsp;
<a href="https://demo.liwan.dev/p/liwan.dev"><img width="45%" src="./data/images/liwan-desktop.png" /></a>
</div>

## Features

- **Quick setup**\
  Quickly get started with Liwan with a single, self-contained binary . No database or complex setup required. The tracking script is a single line of code that works with any website and less than 1KB in size.
- **Privacy first**\
  Liwan respects your users’ privacy by default. No cookies, no cross-site tracking, no persistent identifiers. All data is stored on your server.
- **Lightweight**\
  You can run Liwan on a cheap VPS, your old mac mini, or even a Raspberry Pi. Written in Rust and using tokio for async I/O, Liwan is fast and efficient.
- **Open source**\
  Fully open source. You can change, extend, and contribute to the codebase.
- **Accurate data**\
  Get accurate data about your website’s visitors, page views, referrers, and more. Liwan detects bots and crawlers and filters them out by default.
- **Real-time analytics**\
  See your website’s traffic in real-time. Liwan updates the dashboard automatically as new visitors come in.

### More details

- **Login options**\
  Sign in with a username and password, or connect your identity provider over OIDC/SSO. With OIDC enabled, a "Sign in with SSO" button appears on the login page and accounts are provisioned automatically on first login. The username is taken from the provider's `preferred_username`, then a verified email, and — when neither is available — the user's name (e.g. `Jane Doe` → `jane-doe`), falling back to the opaque subject ID only as a last resort; either way, the account is matched on the provider's subject, so email or name changes never break the link. The first admin is created through a one-time setup flow, and accounts can also be managed from the CLI.
- **Multiple sites in one instance**\
  Track as many websites and apps as you like. Each tracked site is an *entity*, and entities are grouped into *projects* that you view together on the dashboard. Projects can be public (viewable without logging in) or private.
- **Multiple users**\
  Liwan is fully multi-user. Admins create accounts from the dashboard or the CLI, set each user's email, and grant access to specific projects.
- **Roles & permissions**\
  Two roles keep things simple: *admins* manage users, projects, entities, and global settings; regular *users* get read-only access to the projects they've been granted plus any public ones. Access is always enforced on the server.
- **What gets tracked**\
  Page views, unique visitors, bounce rate, and time on site — broken down by page, referrer, UTM campaign, browser, OS, device type, screen size, and country or city (optional GeoIP). Capture custom events too, via the one-line tracking script, the `liwan-tracker` npm package, or a plain HTTP endpoint. Bots are filtered out by default, and configurable drop rules and retention policies let you decide exactly what's stored.

## Configuration

Liwan reads a single TOML file. It looks for `./liwan.config.toml`, then `$XDG_CONFIG_HOME/liwan/config.toml` (i.e. `~/.config/liwan/config.toml`), or you can point it at an explicit path with `--config <path>` or the `LIWAN_CONFIG` env var. Any value can also be overridden with a `LIWAN_*` environment variable (e.g. `LIWAN_OIDC_CLIENT_SECRET`), which is the recommended way to pass secrets. A fully annotated example lives in [`data/config.example.toml`](data/config.example.toml).

```toml
base_url = "https://analytics.example.com"  # external URL of this instance (used to build the OIDC redirect URI)
listen   = 9042                             # local http port to bind, typically behind a reverse proxy
# data_dir = "./liwan-data"                 # defaults to ~/.local/share/liwan/data
```

### OpenID Connect (OIDC)

Add an `[oidc]` section to enable SSO. It only activates once `issuer`, `client_id`, and `client_secret` are all set — at which point a "Sign in with SSO" button appears on the login page. Password login keeps working alongside it.

```toml
[oidc]
issuer        = "https://idp.example.com"        # discovery base; /.well-known/openid-configuration is appended
client_id     = "liwan"
client_secret = "..."                            # prefer the LIWAN_OIDC_CLIENT_SECRET env var
scopes        = ["openid", "email", "profile"]   # optional; this is the default
button_label  = "Sign in with SSO"               # optional; label on the login button
```

Register this redirect URI with your provider (derived from `base_url`):

```
<base_url>/api/dashboard/auth/oidc/callback
```

First-time SSO users are created as regular users with no project access until an admin grants it; usernames are derived from the OIDC claims as described under [Login options](#more-details). Accounts are matched on the provider's subject, so a later email or name change never breaks the link.

## Fork

This is a fork of [explodingcamera/liwan](https://github.com/explodingcamera/liwan), adding support for an OIDC/OAuth login flow.

## License

Unless otherwise noted, the code in this repository is available under the terms of the Apache-2.0 license. See [LICENSE](LICENSE.md) for more information.
