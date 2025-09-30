# Tailscale VPN gateway

A small application that connects to Tailscale, advertises itself as an
app connector and exit node, and punts all incoming traffic over a wireguard
VPN connection.

All the networking code runs in userspace, so the whole thing can run in an
unprivileged docker container.

Use this if you want to:

- Have an exit node that transits over a commercial VPN other than Mullvad
- Have an exit node that uses Mullvad without Tailscale knowing about it
- Route some websites over a VPN to avoid geo-blocking, age-gating, and other pains

## Running

The recommended way to run tsv is via Docker. Here's a sample compose file:

```yaml
services:
  tsv:
    image: ghcr.io/csmith/tsv:latest
    restart: always
    environment:
      # Minimum required settings:
      WG_PRIVATE_KEY:   # private key 
      WG_PUBLIC_KEY:    # public key
      WG_ADDRESS:       # client addresses (comma-separated)
      WG_ENDPOINT:      # remote endpoint (can be ip:port or host:port)
      
      # Optional wireguard settings:
      WG_PRESHARED_KEY: # pre-shared key
      WG_DNS:           # DNS servers (comma-separated, defaults to 9.9.9.9)
      WG_MTU:           # MTU (defaults to 1420)
      WG_ALLOWED_IPS:   # Allowed IP ranges (comma-separated defaults to 0.0.0.0/0,::/0)
      
      # Optional healthcheck settings:
      WG_HEALTH_CHECK_URL:    # URL to request to check connectivity, should return a 204 (default https://www.gstatic.com/generate_204)
      WG_HEALTH_CHECK_PERIOD: # How often to check connectivity (default 30s) 

      # Optional tailscale settings:
      TAILSCALE_HOSTNAME:   # Hostname to advertise on the tailnet (default tsv)
      TAILSCALE_CONFIG_DIR: # Directory to persist tailscale state (default /config)

      # Optional logging settings
      LOG_LEVEL:  # logging level: debug, info, warn, or error (default info)
      LOG_FORMAT: # logging format: text or json (default text)
    volumes:
      - tailscale:/config

volumes:
  tailscale:  
```

When you first run `tsv`, look at the logs for the link to authorise the node
with Tailscale.

Configure the node as either an exit node or as an app connector (or both) in
the Tailscale admin console

## Provenance

This project was primarily created with Claude Code, but with a strong guiding
hand. It's not "vibe coded", but an LLM was still the primary author of most
lines of code. I believe it meets the same sort of standards I'd aim for with
hand-crafted code, but some slop may slip through. I understand if you
prefer not to use LLM-created software, and welcome human-authored alternatives
(I just don't personally have the time/motivation to do so).
