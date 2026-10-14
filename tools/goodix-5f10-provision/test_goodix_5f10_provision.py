#!/usr/bin/env python3
"""Offline tests for goodix_5f10_provision.py - no hardware, no pyusb needed.

Runs the tool's own transport logic (command(), psk_read(), psk_write(),
bring_up(), main()) against a scripted wire that decodes the real frames with
the module's own frame code. Covers the dry-run default, write with a full
reply, write answered with only an ack, ack+reply, and a stuck write.
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import goodix_psk_tlv as t  # noqa: E402
import goodix_5f10_provision as m  # noqa: E402

_FAKE = {}


def _le32(v: int) -> bytes:
    return v.to_bytes(4, "little")


def parse_tlv2(payload: bytes):
    """Extract the TLV-1 body from a command-0xE0 payload (what the MCU stores)."""
    assert len(payload) >= 36
    assert int.from_bytes(payload[0:4], "little") == 0xBB010002
    sealed_len = int.from_bytes(payload[4:8], "little") - 8
    tag1_off = 8 + sealed_len + 8
    assert int.from_bytes(payload[tag1_off:tag1_off + 4], "little") == 0xBB010003
    return payload[tag1_off + 8:tag1_off + 8 + 102]


class ProvisionTests(unittest.TestCase):
    """Monkey-patches the CLI's wire primitives; everything else is the real code."""

    def setUp(self):
        real = self.real_cls = m.Goodix5F10
        self._saved = (real.__init__, real._write, real._read_pack)

        def fake_init(self, verbose=False):
            self.verbose = verbose
            self._usb_util = types.SimpleNamespace(
                release_interface=lambda *a, **k: None)
            self.dev = object()
            self._rx = []          # frames the "chip" still has to send
            self.stored = _FAKE.get("stored")            # hash or None
            self.corrupt_write = _FAKE.get("corrupt_write", False)
            self.write_answer = _FAKE.get("write_answer", "reply")  # reply|ack|both
            self.sent_cmds = []
            self.sent_payloads = {}
            self.enable_payload = None
            _FAKE["dev"] = self

        def fake_write(self, frame):
            flags, cmd, payload = real._decode_protocol(frame)
            self.sent_cmds.append(cmd)
            self.sent_payloads.setdefault(cmd, []).append(bytes(payload))
            if cmd == t.GOODIX_CMD_PRESET_PSK_READ:
                if self.stored is None:
                    self._rx.append(t.command_frame(cmd, b"\x01"))
                else:
                    reply = b"\x00" + _le32(0xBB020003) + _le32(32) + self.stored
                    self._rx.append(t.command_frame(cmd, reply))
            elif cmd == t.GOODIX_CMD_PRESET_PSK_WRITE:
                if self.corrupt_write:
                    self.stored = b"\xaa" * 32
                else:
                    self.stored = hashlib.sha256(parse_tlv2(payload)).digest()
                if self.write_answer == "ack":
                    self._rx.append(t.command_frame(m.CMD_ACK, bytes([cmd])))
                elif self.write_answer == "both":
                    self._rx.append(t.command_frame(cmd, b"\x00"))
                    self._rx.append(t.command_frame(m.CMD_ACK, bytes([cmd])))
                else:  # reply
                    self._rx.append(t.command_frame(cmd, b"\x00"))
            elif cmd == m.CMD_ENABLE_CHIP:
                self.enable_payload = payload
                drops = _FAKE.get("drop_enable_acks", 0)
                if drops > 0:
                    # simulate the hardware transient: the chip never acks
                    _FAKE["drop_enable_acks"] = drops - 1
                else:
                    self._rx.append(t.command_frame(m.CMD_ACK, bytes([cmd])))
            elif cmd == m.CMD_QUERY_MCU_STATE:
                self._rx.append(t.command_frame(cmd, b"\x00\x00"))
            elif cmd == m.CMD_FIRMWARE_VERSION:
                self._rx.append(t.command_frame(cmd, b"GF_ST411SEC_APP_12705\x00"))
            # CMD_NOP expects no reply

        def fake_read_pack(self, timeout_ms=1000):
            if not self._rx:
                raise m.Timeout("scripted chip: no reply queued")
            return self._rx.pop(0)

        real.__init__ = fake_init
        real._write = fake_write
        real._read_pack = fake_read_pack
        _FAKE.clear()
        self.tmp = tempfile.mkdtemp(prefix="g5f10-test-")
        self._real_sleep = m.time.sleep
        self.sleeps = []
        m.time.sleep = lambda s: self.sleeps.append(s)

    def tearDown(self):
        real = self.real_cls
        real.__init__, real._write, real._read_pack = self._saved
        m.time.sleep = self._real_sleep

    def path(self, name):
        return os.path.join(self.tmp, name)

    def read_file(self, name):
        with open(self.path(name), "rb") as fh:
            return fh.read()

    def test_dry_run_is_read_only(self):
        rc = m.main(["--psk-file", self.path("psk")])
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(self.path("psk")))
        dev = _FAKE["dev"]
        # the default path only reads: bring-up + 0xE4, never 0xE0
        self.assertIn(t.GOODIX_CMD_PRESET_PSK_READ, dev.sent_cmds)
        self.assertNotIn(t.GOODIX_CMD_PRESET_PSK_WRITE, dev.sent_cmds)
        # the 0xE4 request carries the driver's hash-object tag
        self.assertEqual(dev.sent_payloads[t.GOODIX_CMD_PRESET_PSK_READ][0],
                         bytes.fromhex("030002bb" "00000000"))

    def test_bring_up_frames_match_driver(self):
        """Every bring-up frame byte must equal what goodix.c emits.

        Pack layout [flags][len16][sum][payload] (goodix_proto.c
        goodix_encode_pack), protocol [cmd][len16=payload+1][payload]
        [0xAA-sum] (goodix_encode_protocol), NULL checksum 0x88
        (GOODIX_NULL_CHECKSUM, goodix_proto.h:26):
        - NOP: GoodixNop{.unknown=0}, calc=FALSE (goodix.c:592)
        - ENABLE_CHIP: bytes 01 02, the 5F10 override (goodix5f10.c:622)
        - QUERY_MCU: GoodixQueryMcuState{.unused_flags=0x55} (goodix.c:980)
        - FW_VERSION: GoodixNone, two zero bytes (goodix.c:955)
        - PSK read: GoodixPresetPsk{flags=LE(0xBB020003), length=0}
          (goodix.c:1085-1086, GOODIX_5F10_PSK_FLAGS in goodix5f10.h:33)
        """
        pad = lambda head, total=64: head + "00" * (total - len(head) // 2)
        expect = {
            "nop": pad("a00800a8" "0005000000000088"),
            "enable": pad("a00600a6" "96030001020e"),
            "query": pad("a00500a5" "ae020055a5"),
            "fw": pad("a00600a6" "a803000000ff"),
            "e4": pad("a00c00ac" "e40900030002bb00000000fd"),
        }
        got = {
            "nop": t.command_frame(0x00, b"\x00" * 4, calc_checksum=False),
            "enable": t.command_frame(m.CMD_ENABLE_CHIP, b"\x01\x02"),
            "query": t.command_frame(m.CMD_QUERY_MCU_STATE, b"\x55"),
            "fw": t.command_frame(m.CMD_FIRMWARE_VERSION, b"\x00\x00"),
            "e4": t.command_frame(t.GOODIX_CMD_PRESET_PSK_READ,
                                  t.psk_read_payload()),
        }
        for name in expect:
            self.assertEqual(got[name].hex(), expect[name], name)

    def test_enable_ignores_stale_ack(self):
        """expect='ack' only accepts the ack naming our command.

        Mirrors goodix_receive_ack (goodix.c:278-282), which warns and
        ignores an ack whose cmd != priv->cmd. Without this, the
        fire-and-forget NOP's late ack would falsely complete enable_chip.
        """
        dev = self.real_cls(verbose=False)
        # a stale NOP ack arrives first, then the real ENABLE ack (queued by
        # fake_write when command() sends)
        dev._rx.append(t.command_frame(m.CMD_ACK, bytes([m.CMD_NOP])))
        dev.enable_chip()
        self.assertEqual(dev.enable_payload, b"\x01\x02")
        self.assertEqual(dev._rx, [])

    def test_psk_read_malformed_is_none(self):
        """A status-0x00 reply that is too short is 'no usable PSK'.

        The driver hard-errors activation on it (goodix.c:201-207); the
        read-only CLI must report instead of raising.
        """
        _FAKE["stored"] = None  # unused here; reply is scripted below
        dev = self.real_cls(verbose=False)
        dev._rx.append(t.command_frame(t.GOODIX_CMD_PRESET_PSK_READ,
                                       b"\x00\x03"))
        flags, data = dev.psk_read()
        self.assertIsNone(flags)
        self.assertIsNone(data)

    def test_read_pack_timeout_reports_partial_bytes(self):
        """A timeout must show the residue, so 'chip silent' (0 bytes) and
        'truncated frame' can be told apart on hardware."""
        import sys as _sys

        saved = {k: _sys.modules.get(k) for k in ("usb", "usb.core")}
        fake_usb = types.ModuleType("usb")
        fake_core = types.ModuleType("usb.core")

        class USBTimeoutError(Exception):
            pass

        fake_core.USBTimeoutError = USBTimeoutError
        fake_usb.core = fake_core
        _sys.modules["usb"] = fake_usb
        _sys.modules["usb.core"] = fake_core
        try:
            dev = self.real_cls(verbose=False)

            class Stub:
                def __init__(self):
                    self.calls = 0

                def read(self, *a, **k):
                    self.calls += 1
                    if self.calls == 1:
                        return b"\xa0\x0c"  # pack header, payload never comes
                    raise USBTimeoutError("timed out")

            dev.dev = Stub()
            with self.assertRaises(m.Timeout) as ctx:
                self._saved[2](dev, 50)
            self.assertIn("a00c", str(ctx.exception))
        finally:
            for k, v in saved.items():
                if v is None:
                    _sys.modules.pop(k, None)
                else:
                    _sys.modules[k] = v

    def test_write_with_full_reply(self):
        _FAKE["write_answer"] = "reply"
        psk = bytes(range(32))
        rc = m.main(["--write", "--psk", psk.hex(), "--psk-file", self.path("psk")])
        self.assertEqual(rc, 0)
        self.assertEqual(self.read_file("psk"), psk)

    def test_write_answered_with_ack_only(self):
        _FAKE["write_answer"] = "ack"
        psk = bytes(range(32))
        rc = m.main(["--write", "--psk", psk.hex(), "--psk-file", self.path("psk")])
        self.assertEqual(rc, 0)
        self.assertEqual(self.read_file("psk"), psk)

    def test_write_answered_with_ack_then_reply(self):
        _FAKE["write_answer"] = "both"
        psk = bytes(range(32))
        rc = m.main(["--write", "--psk", psk.hex(), "--psk-file", self.path("psk")])
        self.assertEqual(rc, 0)
        self.assertEqual(self.read_file("psk"), psk)

    def test_write_that_does_not_stick_is_not_saved(self):
        _FAKE["write_answer"] = "reply"
        _FAKE["corrupt_write"] = True
        psk = bytes(range(32))
        rc = m.main(["--write", "--psk", psk.hex(), "--psk-file", self.path("psk")])
        self.assertEqual(rc, 4)
        self.assertFalse(os.path.exists(self.path("psk")))

    def test_write_from_file_reuses_the_key(self):
        _FAKE["write_answer"] = "reply"
        src = self.path("src.psk")
        psk = bytes(range(32))
        with open(src, "wb") as fh:
            fh.write(psk)
        rc = m.main(["--psk-from-file", src, "--psk-file", self.path("out.psk")])
        self.assertEqual(rc, 0)
        self.assertEqual(self.read_file("out.psk"), psk)

    def test_write_from_file_missing_is_an_error(self):
        with self.assertRaises(SystemExit):
            m.main(["--psk-from-file", self.path("nope.psk"),
                    "--psk-file", self.path("out.psk")])
        self.assertFalse(os.path.exists(self.path("out.psk")))

    def test_bring_up_enable_chip_matches_driver(self):
        """goodix5f10.c send_enable_chip sends bytes 01 02 (5F10 override)."""
        dev = self.real_cls(verbose=False)
        dev.bring_up()
        self.assertEqual(dev.enable_payload, b"\x01\x02")

    def test_bring_up_settles_before_first_command(self):
        """bring_up() pauses once before the first NOP (USB settle).

        The driver settles implicitly via fprintd's open path; the CLI must
        wait explicitly so the first 0x96 is not sent into a just-claimed
        interface. 0 disables the pause.
        """
        dev = self.real_cls(verbose=False)
        dev.bring_up()
        self.assertEqual(self.sleeps, [m.SETTLE_AFTER_CLAIM_MS / 1000.0])

    def test_bring_up_settle_zero_skips_sleep(self):
        rc = m.main(["--psk-file", self.path("psk"), "--settle-ms", "0"])
        self.assertEqual(rc, 0)
        self.assertEqual(self.sleeps, [])

    def test_enable_retries_once_after_silence(self):
        """A single identical 0x96 resend recovers the observed transient.

        On hardware the first 0x96 after a fresh claim is intermittently
        never acked ("have 0 bytes") while everything after it succeeds.
        """
        _FAKE["drop_enable_acks"] = 1
        dev = self.real_cls(verbose=False)
        dev.enable_chip()  # must not raise
        self.assertEqual(dev.enable_payload, b"\x01\x02")
        self.assertEqual(dev.sent_cmds, [m.CMD_ENABLE_CHIP] * 2)
        for sent in dev.sent_payloads[m.CMD_ENABLE_CHIP]:
            self.assertEqual(sent, b"\x01\x02")
        self.assertEqual(dev._rx, [])

    def test_enable_double_silence_still_continues(self):
        """Two silent 0x96 in a row stay non-fatal (later nudges re-sync)."""
        _FAKE["drop_enable_acks"] = 99
        dev = self.real_cls(verbose=False)
        dev.enable_chip()  # must not raise
        self.assertEqual(dev.sent_cmds, [m.CMD_ENABLE_CHIP] * 2)

    def test_psk_read_payload_matches_driver(self):
        """0xE4 read must carry the driver's hash-object tag 0xBB020003.

        The MCU refuses other tags (e.g. the 0xBB010003 key object) with status
        0x01, which the CLI reports as "Current PSK: none"
        while the driver reads the key.
        """
        payload = t.psk_read_payload()
        self.assertEqual(payload, _le32(0xBB020003) + _le32(0))
        frame = t.command_frame(t.GOODIX_CMD_PRESET_PSK_READ, payload)
        flags, cmd, sent = self.real_cls._decode_protocol(frame)
        self.assertEqual(flags, 0xA0)
        self.assertEqual(cmd, 0xE4)
        # exact bytes the driver puts on the wire: [flags LE32][length LE32 0]
        self.assertEqual(sent, bytes.fromhex("030002bb" "00000000"))

    def test_wire_frame_is_well_formed(self):
        """The frames the module sends must decode with the module's own reader."""
        dev = self.real_cls(verbose=False)
        blob = t.build_write_payload(bytes(32), sealed=os.urandom(324),
                                     seed=os.urandom(8))
        frame = t.command_frame(t.GOODIX_CMD_PRESET_PSK_WRITE, blob)
        flags, cmd, payload = self.real_cls._decode_protocol(frame)
        self.assertEqual(flags, 0xA0)
        self.assertEqual(cmd, 0xE0)
        self.assertEqual(payload, blob)


if __name__ == "__main__":
    unittest.main()