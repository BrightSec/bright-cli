# Bright CLI Helm Chart

Bright CLI Repeater lets you run Bright security scans without exposing your internal applications to the Internet.

The Repeater acts as a secure proxy that connects to your local targets and forwards scan requests from the Bright cloud engine.

Prerequisites:

- Active Bright account (`https://app.brightsec.com/`)
- Valid API token with `bot` scopes
- Repeater ID from the Bright app

## Install the Chart

To install the Bright CLI Helm chart, you need to execute the following command:

```bash
helm install bright-cli oci://ghcr.io/brightsec/bright-cli \
--set api.hostname="app.brightsec.com" \
--set api.token="your-brightsec-api-token" \
--set repeater.id="your-repeater-id"
```

> **Note**: By default, the chart connects to `app.brightsec.com`.

To use a different Bright instance, set `--set api.hostname="your-bright-hostname"`.

You can also pass additional repeater arguments using `--set repeater.extraArgs.key=value`.

### Using an Existing Kubernetes Secret

If you prefer to manage your API token using an existing Kubernetes secret (recommended for production), you can reference it instead of passing the token in plain text:

1. First, create your secret:

```bash
kubectl create secret generic my-bright-secret \
  --from-literal=token="your-brightsec-api-token"
```

2. Then install the chart referencing the existing secret:

```bash
helm install bright-cli oci://ghcr.io/brightsec/bright-cli \
--set api.hostname="app.brightsec.com" \
--set api.existingSecret.name="my-bright-secret" \
--set repeater.id="your-repeater-id"
```

> **Note**: When using `api.existingSecret.name`, the chart will not create its own secret and will reference the existing one instead. The `api.existingSecret.key` defaults to `token` if not specified.

## Upgrade the Chart

If you need to upgrade the chart, you can use the following command:

```bash
helm upgrade bright-cli oci://ghcr.io/brightsec/bright-cli
```

## Uninstalling the Chart

To uninstall the chart, run:

```bash
helm uninstall bright-cli
```
