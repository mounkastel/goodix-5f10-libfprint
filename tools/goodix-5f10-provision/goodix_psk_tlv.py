#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Goodix 27c6:5F10 presets ("TLV-1") packer - pure Python.

Fixed constant of the sensor protocol; identical on every host.
Test vectors: see tests/ for the expected output (see ``test_goodix_psk_tlv.py``).

Everything here is static: the key material below is the same on every host.
There is no per-machine secret involved in this step - it is a wrapping of a key
the host generated, not encryption of a factory secret.

------------------------------------------------- packer output --------
``tlv1_body(psk)`` produces a 102-byte "TLV-1 body":

    body = HMAC(32) || MAGIC(2) || LEN(4) || IV(16) || CT(32) || TAG(16)

with

    KDF48       = 58f013ee...   (48 bytes, static; see note below)
    AES key     = KDF48[0:32]
    HMAC key    = KDF48[16:48]
    MAGIC       = 0xFF02 (LE16)
    LEN         = 32 (LE32)
    IV          = SHA256( MAGIC || LEN || PSK[0:8] || LE32(3) x 16 )[0:16]
    AAD         = 522dc1f099567d07f47f37a32a84427d
    CT,TAG      = AES-256-GCM(KDF48[0:32], IV, AAD, PSK)   (standard GCM)
    HMAC(32)    = HMAC-SHA256( KDF48[16:48], MAGIC || LEN || CT || TAG )

NOTE on KDF48. Fixed constant of the sensor protocol; identical on every host.

"TLV-2" (the payload actually written to the MCU with command 0xE0) is:

    [0xBB010002][len(sealed)+8][sealed...][seed(8)][0xBB010003][102][body]

where ``sealed`` is the *host backup* blob (which the
MCU stores but never interprets) and ``seed`` is 8 random bytes.  Only the
``0xBB010003`` body matters to the MCU; the ``0xBB010002`` section exists so a
host can read its own backup back for restore.
"""

from __future__ import annotations

import hashlib
import hmac
import os

try:  # prefer `cryptography` (common on Linux); fall back to pycryptodome
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    def _aes_gcm_encrypt(key: bytes, nonce: bytes, aad: bytes, pt: bytes):
        out = AESGCM(key).encrypt(nonce, pt, aad)
        return out[:-16], out[-16:]

except ImportError:  # pragma: no cover - exercised only without `cryptography`
    from Crypto.Cipher import AES

    def _aes_gcm_encrypt(key: bytes, nonce: bytes, aad: bytes, pt: bytes):
        c = AES.new(key, AES.MODE_GCM, nonce=nonce)
        c.update(aad)
        return c.encrypt_and_digest(pt)


# ---------------------------------------------------------------------------
# Static material. Fixed constant of the sensor protocol; identical on every host.
# ---------------------------------------------------------------------------
KDF48 = bytes.fromhex(
    "58f013eeb7e216e2c1cd0e8fffa7dbd6799cd92aa149013ea0e9f9fd7dc6d94e"
    "3ef63a7598c2a4933129e871ea03043b"
)
AAD = bytes.fromhex("522dc1f099567d07f47f37a32a84427d")

TLV1_TAG = 0xBB010003  # the encrypted-PSK object the MCU stores
TLV2_TAG = 0xBB010002  # the host-backup object the MCU only stores

# The only tag the MCU answers a 0xE4 *read* of with data (status 0x00 plus the
# 32-byte SHA256(TLV-1 body)) is the "hash" object, 0xBB020003. A read of the
# key object tag 0xBB010003 is refused with status 0x01 (write-only from the
# chip's point of view). This must equal the driver's GOODIX_5F10_PSK_FLAGS,
# see goodix5f10.h.
PSK_READ_FLAGS = 0xBB020003

MAGIC = 0xFF02

PSK_LEN = 32  # the 5F10 TLS-PSK is 32 bytes


def _le16(v: int) -> bytes:
    return v.to_bytes(2, "little")


def _le32(v: int) -> bytes:
    return v.to_bytes(4, "little")


def tlv1_body(psk: bytes) -> bytes:
    """PSK(32) -> the 102-byte TLV-1 body (no 0xBB010003 tag/length header).

    Test vectors: see tests/ for the expected output.
    """
    if len(psk) != PSK_LEN:
        raise ValueError(f"PSK must be {PSK_LEN} bytes, got {len(psk)}")

    n = len(psk)
    header = _le16(MAGIC) + _le32(n)
    # IV = SHA256(MAGIC || LEN || PSK[0:n/4] || LE32(3) x 16)[:16]
    iv = hashlib.sha256(header + psk[: n // 4] + _le32(3) * 16).digest()[:16]

    ct, tag = _aes_gcm_encrypt(KDF48[:32], iv, AAD, psk)

    outer = hmac.new(KDF48[16:48], header + ct + tag, hashlib.sha256).digest()
    return outer + header + iv + ct + tag


def tlv1_frame(psk: bytes) -> bytes:
    """The full ``0xBB010003`` object: [tag][len][102-byte body]."""
    body = tlv1_body(psk)
    return _le32(TLV1_TAG) + _le32(len(body)) + body


def host_hash(psk: bytes) -> bytes:
    """What the MCU returns for a 0xE4 read of flags 0xBB020003.

    SHA256(TLV-1 body); the MCU is expected to carry the same value, which is
    how a write is verified.
    """
    return hashlib.sha256(tlv1_body(psk)).digest()


def build_write_payload(psk: bytes, sealed: bytes | None = None,
                        seed: bytes | None = None) -> bytes:
    """Build the full payload for PSK-write command 0xE0 (the "TLV-2" blob).

    ``sealed`` is the host-backup blob. The MCU stores it verbatim and never
    reads it, so any bytes work. ``seed`` is 8 random bytes. The result is
    zero-padded to a multiple of 4.
    """
    body = tlv1_body(psk)
    if sealed is None:
        sealed = os.urandom(324)  # host-backup blob size
    if seed is None:
        seed = os.urandom(8)
    if len(seed) != 8:
        raise ValueError("seed must be 8 bytes")

    out = bytearray()
    out += _le32(TLV2_TAG)
    out += _le32(len(sealed) + 8)
    out += sealed
    out += seed
    out += _le32(TLV1_TAG)
    out += _le32(len(body))
    out += body

    while len(out) % 4:
        out.append(0)
    return bytes(out)


# ---------------------------------------------------------------------------
# Goodix wire framing (mirrors libfprint goodix_proto.c exactly).
# ---------------------------------------------------------------------------
GOODIX_FLAGS_MSG_PROTOCOL = 0xA0
GOODIX_CMD_PRESET_PSK_READ = 0xE4
GOODIX_CMD_PRESET_PSK_WRITE = 0xE0
GOODIX_NULL_CHECKSUM = 0x88


def _checksum(data: bytes) -> int:
    return sum(data) & 0xFF


def encode_protocol(cmd: int, payload: bytes, calc_checksum: bool = True,
                    pad_data: bool = False) -> bytes:
    """[cmd][len16][payload][checksum], optionally padded to 64."""
    frame = bytearray()
    frame.append(cmd & 0xFF)
    frame += _le16(len(payload) + 1)
    frame += payload
    if calc_checksum:
        frame.append((0xAA - _checksum(bytes(frame))) & 0xFF)
    else:
        frame.append(GOODIX_NULL_CHECKSUM)
    return _pad(frame, pad_data)


def encode_pack(flags: int, payload: bytes, pad_data: bool = True) -> bytes:
    """[flags][len16][checksum][payload], optionally padded to 64."""
    frame = bytearray()
    frame.append(flags & 0xFF)
    frame += _le16(len(payload))
    frame.append(_checksum(bytes(frame)))
    frame += payload
    return _pad(frame, pad_data)


def _pad(data: bytearray, pad_data: bool) -> bytes:
    if pad_data and len(data) % 64:
        data += bytes(64 - len(data) % 64)
    return bytes(data)


def command_frame(cmd: int, payload: bytes, calc_checksum: bool = True) -> bytes:
    """Full pre-TLS USB frame for a command: pack(0xA0, protocol(cmd, payload))."""
    proto = encode_protocol(cmd, payload, calc_checksum=calc_checksum, pad_data=False)
    return encode_pack(GOODIX_FLAGS_MSG_PROTOCOL, proto, pad_data=True)


def psk_read_payload(flags: int = PSK_READ_FLAGS) -> bytes:
    """GoodixPresetPsk{flags, length=0} for a 0xE4 read.

    The read must use the 0xBB020003 hash-object tag (the same value as the
    driver's GOODIX_5F10_PSK_FLAGS): the MCU answers that tag with the stored
    hash, and refuses other tags (e.g. the 0xBB010003 key object) with status
    0x01, which both the CLI and the driver treat as "no usable PSK".
    """
    return _le32(flags) + _le32(0)


def parse_psk_read_reply(reply: bytes):
    """Parse a 0xE4 reply.

    Returns ``(flags, data)`` or raises ValueError.  ``reply`` is the *protocol
    payload* (i.e. everything after the [cmd][len] header), which is what the
    Linux driver's callback receives.  Layout: [status(1)][flags(4)][len(4)][data].
    """
    if len(reply) < 9:
        raise ValueError(f"short PSK read reply ({len(reply)} bytes)")
    status = reply[0]
    if status != 0x00:
        raise ValueError(f"MCU refused PSK read (status 0x{status:02x})")
    flags = int.from_bytes(reply[1:5], "little")
    length = int.from_bytes(reply[5:9], "little")
    data = reply[9:9 + length]
    if len(data) != length:
        raise ValueError("truncated PSK read reply")
    return flags, data
