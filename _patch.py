"""
Monkey-patch qh3's TLS Context to support mutual TLS (client certificates).

Strategy
--------
1. Hook ``push_encrypted_extensions`` to set a flag after EncryptedExtensions is
   written to the handshake buffer.
2. Hook ``push_message`` to inject a CertificateRequest (with its own transcript
   hash scope) *before* the Certificate message's scope opens, and install a
   hash-snapshot wrapper on ``update_hash`` so we can capture the transcript state
   before the server's Finished anticipation.
3. After the original ``_server_handle_hello`` returns, restore the key-schedule
   hash to the pre-anticipation snapshot and transition to custom states that
   expect the client's Certificate, CertificateVerify, and Finished.
4. Handle those three messages in ``_patched_handle_message``, then hand control
   back to qh3's original ``handle_message`` for the Finished verification.
"""

import ssl
import threading
from contextlib import contextmanager

from qh3._hazmat import (
    Buffer,
    Certificate as X509Certificate,
    verify_with_public_key,
    SignatureError,
)
from qh3.tls import (
    Context,
    State,
    HandshakeType,
    ExtensionType,
    SignatureAlgorithm,
    push_block,
    push_opaque,
    pull_certificate,
    pull_certificate_verify,
    AlertBadCertificate,
    AlertDecryptError,
)

# ---------------------------------------------------------------------------
# Custom server states (plain ints, not State enum members)
# ---------------------------------------------------------------------------
SERVER_EXPECT_CLIENT_CERT = 11
SERVER_EXPECT_CLIENT_CERT_VERIFY = 12
_STATE_NAMES = {
    SERVER_EXPECT_CLIENT_CERT: "SERVER_EXPECT_CLIENT_CERT",
    SERVER_EXPECT_CLIENT_CERT_VERIFY: "SERVER_EXPECT_CLIENT_CERT_VERIFY",
}

# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------
_hook = threading.local()
_original_server_handle_hello = Context._server_handle_hello
_original_handle_message = Context.handle_message
_original_push_message = None
_original_push_encrypted_extensions = None
_applied = False


# ---------------------------------------------------------------------------
# CertificateRequest builder
# ---------------------------------------------------------------------------
def _write_certificate_request_bytes(buf: Buffer) -> None:
    buf.push_uint8(HandshakeType.CERTIFICATE_REQUEST)
    with push_block(buf, 3):
        push_opaque(buf, 1, b"")  # empty request_context
        with push_block(buf, 2):  # extensions
            buf.push_uint16(ExtensionType.SIGNATURE_ALGORITHMS)
            with push_block(buf, 2):
                with push_block(buf, 2):
                    buf.push_uint16(SignatureAlgorithm.ED25519)


# ---------------------------------------------------------------------------
# Hooked functions
# ---------------------------------------------------------------------------
def _hooked_push_encrypted_extensions(buf, ee):
    _original_push_encrypted_extensions(buf, ee)
    if getattr(_hook, "ctx", None) is not None:
        _hook.inject_cert_request = True


@contextmanager
def _hooked_push_message(key_schedule, buf):
    if getattr(_hook, "inject_cert_request", False):
        _hook.inject_cert_request = False
        ctx = _hook.ctx
        _hook.ctx = None

        # Write CertificateRequest and hash it in its own scope
        hash_start = buf.tell()
        _write_certificate_request_bytes(buf)
        key_schedule.update_hash(buf.data_slice(hash_start, buf.tell()))
        ctx._requested_client_cert = True

        # Capture pre-anticipation hash on every update_hash call; the last
        # snapshot will be from just before the Finished anticipation.
        orig_uh = type(key_schedule).update_hash

        def capturing_update_hash(data, _orig=orig_uh, _ks=key_schedule):
            _hook.pre_anticipation_hash = _ks.hash.copy()
            _orig(_ks, data)

        key_schedule.update_hash = capturing_update_hash

    # Normal push_message behavior
    hash_start = buf.tell()
    yield
    key_schedule.update_hash(buf.data_slice(hash_start, buf.tell()))


# ---------------------------------------------------------------------------
# Patched Context methods
# ---------------------------------------------------------------------------
def _patched_server_handle_hello(self, input_buf, initial_buf, handshake_buf, onertt_buf):
    self._requested_client_cert = False

    if self._verify_mode == ssl.CERT_NONE:
        return _original_server_handle_hello(self, input_buf, initial_buf, handshake_buf, onertt_buf)

    _hook.ctx = self
    _hook.inject_cert_request = False
    _hook.pre_anticipation_hash = None

    try:
        _original_server_handle_hello(self, input_buf, initial_buf, handshake_buf, onertt_buf)
    finally:
        _hook.ctx = None
        _hook.inject_cert_request = False

    if not self._requested_client_cert:
        return

    # Restore key_schedule hash to pre-anticipation state
    if _hook.pre_anticipation_hash is not None:
        self.key_schedule.hash = _hook.pre_anticipation_hash

    # Remove the capturing wrapper
    ks = self.key_schedule
    ks.update_hash = lambda data, _ks=ks: type(_ks).update_hash(_ks, data)

    self._set_state(SERVER_EXPECT_CLIENT_CERT)


def _patched_handle_message(self, input_data, output_buf):
    if self.state not in (SERVER_EXPECT_CLIENT_CERT, SERVER_EXPECT_CLIENT_CERT_VERIFY):
        if self.state == State.SERVER_EXPECT_FINISHED and getattr(self, "_requested_client_cert", False):
            self._expected_verify_data = self.key_schedule.finished_verify_data(self._dec_key)
            self._requested_client_cert = False
        return _original_handle_message(self, input_data, output_buf)

    self._receive_buffer += input_data
    while len(self._receive_buffer) >= 4:
        message_type = self._receive_buffer[0]
        message_length = 4 + int.from_bytes(self._receive_buffer[1:4], byteorder="big")
        if len(self._receive_buffer) < message_length:
            break
        message = self._receive_buffer[:message_length]
        self._receive_buffer = self._receive_buffer[message_length:]
        input_buf = Buffer(data=message)

        if self.state == SERVER_EXPECT_CLIENT_CERT:
            if message_type != HandshakeType.CERTIFICATE:
                raise AlertBadCertificate("Expected client certificate")
            certificate = pull_certificate(input_buf)
            self.key_schedule.update_hash(input_buf.data)
            if certificate.certificates:
                self._peer_certificate = X509Certificate(certificate.certificates[0][0])
                self._peer_certificate_chain = [
                    X509Certificate(certificate.certificates[i][0])
                    for i in range(1, len(certificate.certificates))
                ]
                self._set_state(SERVER_EXPECT_CLIENT_CERT_VERIFY)
            else:
                self._peer_certificate = None
                self._peer_certificate_chain = []
                self._set_state(State.SERVER_EXPECT_FINISHED)

        elif self.state == SERVER_EXPECT_CLIENT_CERT_VERIFY:
            if message_type != HandshakeType.CERTIFICATE_VERIFY:
                raise AlertBadCertificate("Expected client certificate verify")
            verify = pull_certificate_verify(input_buf)
            try:
                verify_with_public_key(
                    self._peer_certificate.public_key(),
                    verify.algorithm,
                    self.key_schedule.certificate_verify_data(b"TLS 1.3, client CertificateVerify"),
                    verify.signature,
                )
            except (SignatureError, Exception) as e:
                raise AlertDecryptError(str(e))
            self.key_schedule.update_hash(input_buf.data)
            self._set_state(State.SERVER_EXPECT_FINISHED)

        else:
            self._receive_buffer = message + self._receive_buffer
            break

        assert input_buf.eof()

    if self._receive_buffer and self.state in (State.SERVER_EXPECT_FINISHED, State.SERVER_POST_HANDSHAKE):
        if getattr(self, "_requested_client_cert", False):
            self._expected_verify_data = self.key_schedule.finished_verify_data(self._dec_key)
            self._requested_client_cert = False
        return _original_handle_message(self, b"", output_buf)


def _patched_set_state(self, state):
    if self._Context__logger:
        old_name = getattr(self.state, "name", _STATE_NAMES.get(self.state, str(self.state)))
        new_name = getattr(state, "name", _STATE_NAMES.get(state, str(state)))
        self._Context__logger.debug("TLS %s -> %s", old_name, new_name)
    self.state = state


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def apply():
    """
    Apply the mutual-TLS patch to qh3.  Safe to call more than once
    (subsequent calls are no-ops).
    """
    global _applied, _original_push_message, _original_push_encrypted_extensions

    if _applied:
        return
    _applied = True

    import qh3.tls as tls_module

    _original_push_message = tls_module.push_message
    _original_push_encrypted_extensions = tls_module.push_encrypted_extensions
    tls_module.push_message = _hooked_push_message
    tls_module.push_encrypted_extensions = _hooked_push_encrypted_extensions

    Context._server_handle_hello = _patched_server_handle_hello
    Context.handle_message = _patched_handle_message
    Context._set_state = _patched_set_state

    original_init = Context.__init__

    def patched_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self._requested_client_cert = False

    Context.__init__ = patched_init
