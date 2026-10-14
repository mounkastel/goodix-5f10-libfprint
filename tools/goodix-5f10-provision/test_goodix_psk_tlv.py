#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Known-answer tests for goodix_psk_tlv.py.

Test vectors: see tests/ for the expected output. Run: ``python test_goodix_psk_tlv.py``.
"""

import hashlib
import sys

import goodix_psk_tlv as t


ANCHORS = {
    bytes(32): "b5e0beeb94c84eb99b883abd5c251073c56b91035c562a91a46c7f3349c36c89",
    bytes(range(32)): "d1ba9a4790f8d47ba8b50043d72b577cdc2d1b701d466197aa741a94fd0f1ec4",
}


def main() -> int:
    ok = True

    for psk, want in ANCHORS.items():
        body = t.tlv1_body(psk)
        got = hashlib.sha256(body).hexdigest()
        match = got == want and len(body) == 102
        ok &= match
        print(f"tlv1_body({psk[:4].hex()}..) len={len(body)} sha256={got[:16]}.. "
              f"match={match}")
        if not match:
            print(f"    want {want}")

    # structural sanity of the write payload
    psk = bytes(range(32))
    payload = t.build_write_payload(psk, sealed=b"\x11" * 324, seed=b"\x22" * 8)
    assert len(payload) % 4 == 0, "payload must be 4-aligned"
    assert payload[0:4] == (0xBB010002).to_bytes(4, "little")
    assert int.from_bytes(payload[4:8], "little") == 324 + 8
    assert payload[8:8 + 324] == b"\x11" * 324
    assert payload[8 + 324:16 + 324] == b"\x22" * 8
    body_off = 16 + 324
    assert payload[body_off:body_off + 4] == (0xBB010003).to_bytes(4, "little")
    assert int.from_bytes(payload[body_off + 4:body_off + 8], "little") == 102
    assert payload[body_off + 8:body_off + 8 + 102] == t.tlv1_body(psk)
    print(f"build_write_payload len={len(payload)} layout ok")

    # framing: pack(0xA0) -> protocol(cmd) -> payload
    frame = t.command_frame(t.GOODIX_CMD_PRESET_PSK_WRITE, payload)
    assert len(frame) % 64 == 0 and frame[0] == 0xA0
    assert frame[4] == 0xE0
    assert int.from_bytes(frame[1:3], "little") == len(payload) + 4
    assert int.from_bytes(frame[5:7], "little") == len(payload) + 1  # protocol len
    print(f"command_frame(0xE0) len={len(frame)} flags=0x{frame[0]:02x} "
          f"cmd=0x{frame[4]:02x}")

    # reply parsing
    flags, data = t.parse_psk_read_reply(
        b"\x00" + (0xBB020003).to_bytes(4, "little") + (32).to_bytes(4, "little")
        + t.host_hash(psk))
    assert flags == 0xBB020003 and data == t.host_hash(psk)
    print("parse_psk_read_reply ok")

    print("ALL_MATCH", ok)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
