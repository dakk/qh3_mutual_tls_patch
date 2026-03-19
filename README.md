# qh3_mutual_tls_patch

Runtime monkey-patch that adds **mutual TLS** (client certificate authentication) support to [qh3](https://github.com/jawah/qh3)'s server-side TLS 1.3 implementation.

## Problem

qh3's TLS 1.3 server does not send a `CertificateRequest` message during the handshake, so the client never presents its certificate. This makes it impossible to use mutual TLS authentication in QUIC servers built with qh3.

## Solution

This package patches qh3's `Context` class at runtime to:

1. Inject a `CertificateRequest` message into the server handshake (after `EncryptedExtensions`, before `Certificate`)
2. Handle the client's `Certificate`, `CertificateVerify`, and `Finished` messages
3. Verify the client's certificate signature using Ed25519

The patch is non-destructive: connections with `verify_mode = ssl.CERT_NONE` are unaffected.

## Installation

```bash
pip install qh3_mutual_tls_patch
```

Or install from source:

```bash
pip install .
```

## Usage

Call `apply()` once before creating any QUIC connections:

```python
import ssl
from qh3_mutual_tls_patch import apply
from qh3.quic.configuration import QuicConfiguration

# Apply the patch (safe to call multiple times)
apply()

# Now you can request client certificates on the server side
config = QuicConfiguration(is_client=False)
config.verify_mode = ssl.CERT_OPTIONAL  # or ssl.CERT_REQUIRED
# ... set certificate, private_key, alpn_protocols, etc.
```

After the handshake, the client's certificate is available via `context.get_peercert()`.

## How it works

The patch hooks three internal qh3 functions:

- **`push_encrypted_extensions`** — sets a flag after `EncryptedExtensions` is written
- **`push_message`** — intercepts the next `push_message` call (for the server `Certificate`) to inject `CertificateRequest` with its own transcript hash scope beforehand
- **`_server_handle_hello`** — wraps the original to restore the key-schedule hash after qh3's Finished-anticipation step, then transitions to custom states

Two custom TLS states (`SERVER_EXPECT_CLIENT_CERT` and `SERVER_EXPECT_CLIENT_CERT_VERIFY`) handle the client's response before handing control back to qh3's `SERVER_EXPECT_FINISHED` state.

## Compatibility

- **qh3** >= 1.2.1
- **Python** >= 3.10

## Limitations

- Only Ed25519 is advertised in the `CertificateRequest` signature algorithms extension.
- The patch relies on qh3 internals and may break with future qh3 releases.

## License

MIT
