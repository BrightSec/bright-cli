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

### Client Certificates on a Smart Card (PKCS#11)

For HTTPS targets that require a client certificate whose private key is on a smart card, USB token or HSM, list the targets under `repeater.pkcs11.certs` and store the token PIN in a Secret:

```bash
kubectl create secret generic card-pin --from-file=pin=./pin.txt

helm install bright-cli oci://ghcr.io/brightsec/bright-cli \
--set api.existingSecret.name="my-bright-secret" \
--set repeater.id="your-repeater-id" \
--set 'repeater.pkcs11.certs[0].hostname=example.com' \
--set repeater.pkcs11.pinSecret.name="card-pin" \
--set repeater.pkcs11.pcscdSocketDir="/run/pcscd"
```

- Each entry of `repeater.pkcs11.certs` becomes one `--pkcs11-cert` option and accepts the same fields (`hostname`, `port`, `token`, `label`, `id`, `cert`, `maxConcurrency`). `label` and `id` select the certificate on the token. Quote `id` (`id: "01"`), because YAML reads `01` as the number 1.
- Entries without `pinFile` or `pinEnv` read the PIN from `repeater.pkcs11.pinSecret`. The PIN file is readable through `repeater.podSecurityContext.fsGroup`, so keep `fsGroup` set if you override the pod security context. Files referenced by an entry (`pinFile`, `cert`) and variables referenced by `pinEnv` must be provided through `repeater.extraVolumes`, `repeater.extraVolumeMounts` and `repeater.extraEnv`, for example a second Secret for a card with a different PIN.
- `repeater.pkcs11.module` defaults to OpenSC (`/usr/lib/opensc-pkcs11.so`), which supports PIV and CAC cards. The image is Alpine Linux: a vendor module must be built for musl. Mount it with `repeater.extraVolumes` and `repeater.extraVolumeMounts`, and add the environment it needs with `repeater.extraEnv`.
- A card reader attached to the node is reached through the node's `pcscd` socket. Run `pcscd` on the node, pin the pod to that node with `repeater.nodeSelector`, and set `repeater.pkcs11.pcscdSocketDir`. This mounts a `hostPath` volume, which only the `privileged` Pod Security level allows, so label the namespace accordingly.
- Use one replica per card: the Repeater logs in to the token once at startup. After a rejected PIN it stops using the token until it is restarted, so that the card is not locked.

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
