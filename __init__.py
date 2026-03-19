"""
qh3_mutual_tls_patch — Monkey-patch for qh3 to support mutual TLS (client certificates).

qh3's built-in TLS 1.3 server implementation does not send a CertificateRequest
message, so the client never presents its certificate. This package patches the
qh3 TLS Context at runtime to inject CertificateRequest into the server handshake
and handle the resulting client Certificate, CertificateVerify, and Finished
messages.

Usage::

    from qh3_mutual_tls_patch import apply
    apply()  # call once, before any QUIC connections

After patching, set ``verify_mode = ssl.CERT_OPTIONAL`` (or ``ssl.CERT_REQUIRED``)
on your server-side ``QuicConfiguration`` to request client certificates.
"""

from ._patch import apply

__all__ = ["apply"]
