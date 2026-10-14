#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Goodix 27c6:5F10 TLS-PSK provisioning tool - Linux only, no Windows needed.

The 5F10's TLS-PSK is *not* a factory secret: the host generates 32 random
bytes, wraps them in a small "TLV" blob and hands them to the MCU with a
pre-TLS command (0xE0). The host then stores a copy of the key for itself.
This tool does the Linux equivalent:

    read current hash (0xE4)  ->  generate PSK  ->  pack  ->  write (0xE0)
                              ->  read hash again  ->  verify  ->  save raw PSK

The packer (goodix_psk_tlv.py) is covered by test vectors. Test vectors: see tests/ for the expected output.

SAFETY.  Nothing is written unless you pass ``--write``.  By default the tool
only opens the sensor, runs the same pre-TLS bring-up the libfprint driver does,
reads and prints the current PSK hash, and shows the frame it *would* send.
The MCU PSK slot is rewritable (the Windows driver re-provisions on mismatch),
but there is no 5F10 firmware image to recover a bricked unit, so the default is
deliberately read-only.

Usage:
    sudo ./goodix_5f10_provision.py                 # read-only diagnostic
    sudo ./goodix_5f10_provision.py --write \\
         --psk-file /var/lib/fprint/goodix-5f10/psk # provision + save
    sudo ./goodix_5f10_provision.py \\
         --psk-from-file /var/lib/fprint/goodix-5f10/psk \\
         --psk-file /var/lib/fprint/goodix-5f10/psk   # reuse the driver's key
"""

from __future__ import annotations

import argparse
import errno
import os
import secrets
import sys
import time

import goodix_psk_tlv as t

VID = 0x27C6
PID = 0x5F10
INTERFACE = 0
EP_IN = 0x81
EP_OUT = 0x01
BUF_IN = 0x10000
OUT_CHUNK = 0x40

DEFAULT_TIMEOUT_MS = 1000
DEFAULT_PSK_FILE = "/var/lib/fprint/goodix-5f10/psk"

# Settle delay before the first bring-up command. After fprintd releases the
# device the USB interface needs a moment before the chip answers reliably;
# without it the very first 0x96 exchange intermittently gets no ack at all
# ("have 0 bytes") while every later command succeeds. The driver never sees
# this because fprintd's open path (claim + async read-loop arming + SSM
# stepping) settles implicitly. Overridable with --settle-ms (0 disables).
SETTLE_AFTER_CLAIM_MS = 500

GOODIX_FLAGS_MSG_PROTOCOL = 0xA0
CMD_ACK = 0xB0
CMD_NOP = 0x00
CMD_ENABLE_CHIP = 0x96
CMD_QUERY_MCU_STATE = 0xAE
CMD_FIRMWARE_VERSION = 0xA8


def log(verbose, *a):
    if verbose:
        print(*a, file=sys.stderr)


class ProtocolError(RuntimeError):
    pass


class Timeout(RuntimeError):
    pass


class Goodix5F10:
    """Minimal pre-TLS transport for the 5F10 (mirrors goodix.c exactly)."""

    def __init__(self, verbose=False):
        try:
            import usb.core
            import usb.util
        except ImportError as exc:  # pragma: no cover
            raise SystemExit("pyusb is required: python3 -m pip install pyusb "
                             "(and libusb).") from exc
        self._usb_util = usb.util
        self.verbose = verbose

        dev = usb.core.find(idVendor=VID, idProduct=PID)
        if dev is None:
            raise SystemExit(f"No Goodix {VID:04x}:{PID:04x} sensor found.")
        self.dev = dev
        try:
            dev.set_configuration()
        except usb.core.USBError as exc:
            # already configured is fine
            if exc.errno not in (errno.EBUSY, None):
                log(verbose, f"set_configuration: {exc}")
        try:
            if dev.is_kernel_driver_active(INTERFACE):
                dev.detach_kernel_driver(INTERFACE)
        except (NotImplementedError, usb.core.USBError):
            pass
        try:
            usb.util.claim_interface(dev, INTERFACE)
        except usb.core.USBError as exc:
            raise SystemExit(
                f"Could not claim interface {INTERFACE}: {exc}.\n"
                "Make sure fprintd is stopped (systemctl stop fprintd) and you "
                "have permission (run as root or install a udev rule).") from exc
        log(verbose, "claimed interface")

    # -- low level ---------------------------------------------------------
    def _write(self, frame: bytes):
        for i in range(0, len(frame), OUT_CHUNK):
            chunk = frame[i:i + OUT_CHUNK]
            self.dev.write(EP_OUT, chunk, timeout=DEFAULT_TIMEOUT_MS)

    def _read_pack(self, timeout_ms: int) -> bytes:
        """Read until one complete GoodixPack frame is available.

        On timeout the partial bytes are kept in the exception message so a
        silent chip ("have 0 bytes") can be told apart from a truncated
        frame. The residue is discarded: the next command starts fresh,
        which is also how the driver re-arms its read (goodix.c
        goodix_receive_data re-submits after every transfer).
        """
        import usb.core

        buf = bytearray()
        deadline = time.monotonic() + timeout_ms / 1000.0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Timeout(f"no reply within {timeout_ms} ms "
                              f"(have {len(buf)} bytes: {bytes(buf).hex()})")
            try:
                data = self.dev.read(EP_IN, BUF_IN, timeout=int(remaining * 1000))
            except usb.core.USBTimeoutError as exc:
                raise Timeout(f"{exc} (have {len(buf)} bytes: "
                              f"{bytes(buf).hex()})") from exc
            buf += bytes(data)
            if len(buf) >= 4:
                plen = int.from_bytes(buf[1:3], "little")
                if len(buf) >= 4 + plen:
                    return bytes(buf[:4 + plen])

    @staticmethod
    def _decode_protocol(pack: bytes):
        """pack payload is the protocol frame: [cmd][len16][payload][checksum]."""
        flags = pack[0]
        plen = int.from_bytes(pack[1:3], "little")
        proto = pack[4:4 + plen]
        if len(proto) < 4:
            raise ProtocolError("short protocol frame")
        cmd = proto[0]
        inner_len = int.from_bytes(proto[1:3], "little")
        payload = proto[3:3 + inner_len - 1]
        return flags, cmd, payload

    def command(self, cmd: int, payload: bytes, calc_checksum=True,
                expect="reply", timeout_ms=DEFAULT_TIMEOUT_MS):
        """Send a pre-TLS command.

        expect: "reply" (wait for the cmd's own reply), "ack" (wait only for the
        chip's ack), "first" (any protocol frame: an ack or the cmd's own reply,
        whichever arrives first - used for object writes whose answer the vendor
        does not parse), or "none" (fire and forget).
        """
        frame = t.command_frame(cmd, payload, calc_checksum=calc_checksum)
        log(self.verbose, f"-> cmd 0x{cmd:02x} payload {len(payload)}B "
                          f"frame {len(frame)}B\n   {frame.hex()}")
        self._write(frame)
        if expect == "none":
            return None

        while True:
            pack = self._read_pack(timeout_ms)
            flags, pcmd, pdata = self._decode_protocol(pack)
            if flags != GOODIX_FLAGS_MSG_PROTOCOL:
                log(self.verbose, f"<- ignoring flags 0x{flags:02x}")
                continue
            if pcmd == CMD_ACK:
                acked = pdata[0] if pdata else None
                log(self.verbose, f"<- ack for 0x{acked:02x} {pdata.hex()}"
                    if acked is not None else "<- ack")
                if expect == "first":
                    return None
                if expect == "ack":
                    # Like the driver's goodix_receive_ack (goodix.c): an ack
                    # only counts when it names the command we just sent. A
                    # stale ack (e.g. the fire-and-forget NOP's) must not
                    # complete the wait.
                    if acked == cmd:
                        return None
                    log(self.verbose,
                        f"<- ignoring ack for 0x{acked:02x}, waiting for "
                        f"0x{cmd:02x}")
                    continue
                continue
            if pcmd == cmd:
                log(self.verbose, f"<- reply 0x{cmd:02x} {len(pdata)}B "
                                  f"{pdata.hex()}")
                return pdata
            log(self.verbose, f"<- ignoring unexpected reply 0x{pcmd:02x} "
                              f"{pdata.hex()}")

    # -- protocol helpers --------------------------------------------------
    def nop(self):
        self.command(CMD_NOP, b"\x00" * 4, calc_checksum=False, expect="none")

    def enable_chip(self):
        # The 5F10 wants ENABLE_CHIP body "01 02" (goodix5f10.c
        # send_enable_chip overrides the generic helper's "01 00").
        # One retry on a silent chip: the first 0x96 after a fresh claim is
        # intermittently never acked ("have 0 bytes") while everything after
        # it succeeds, so a single identical resend recovers without changing
        # any wire bytes. A second silence is non-fatal: later nudges
        # (QUERY_MCU/NOP, which the driver itself treats as state nudges)
        # re-sync the chip, as proven by 0xE4 reads succeeding after such
        # timeouts on hardware.
        for attempt in (1, 2):
            try:
                self.command(CMD_ENABLE_CHIP, b"\x01\x02", expect="ack")
                return
            except Timeout as exc:
                if attempt == 1:
                    log(self.verbose, f"enable_chip: {exc} (retrying once)")
                else:
                    log(self.verbose, f"enable_chip: {exc} (continuing)")

    def query_mcu(self):
        return self.command(CMD_QUERY_MCU_STATE, b"\x55")

    def firmware_version(self) -> str:
        data = self.command(CMD_FIRMWARE_VERSION, b"\x00\x00")
        raw = bytes(data).split(b"\x00", 1)[0]
        try:
            return raw.decode("ascii", "replace")
        except Exception:
            return raw.hex()

    def psk_read(self):
        """Return (flags, data) for a 0xBB020003 read, or (None, None) if none.

        Anything the chip answers that is not a well-formed success reply
        (refusal status, short or truncated frame) means "no usable PSK",
        exactly like the driver's success=FALSE path in
        goodix_receive_preset_psk_read (goodix.c). It never raises: the
        read-only diagnostic must report, not crash.
        """
        payload = t.psk_read_payload()
        reply = self.command(t.GOODIX_CMD_PRESET_PSK_READ, payload)
        if reply is None or len(reply) < 1 or reply[0] != 0x00:
            return None, None
        try:
            return t.parse_psk_read_reply(reply)
        except ValueError as exc:
            log(self.verbose, f"psk_read: malformed 0xE4 reply "
                              f"({len(reply)}B {bytes(reply).hex()}): {exc}")
            return None, None

    def psk_write(self, blob: bytes):
        self.command(t.GOODIX_CMD_PRESET_PSK_WRITE, blob, expect="first")

    def bring_up(self, settle_ms: int = SETTLE_AFTER_CLAIM_MS):
        """Same pre-TLS sequence as goodix5f10.c activate_run_state.

        Starts with a short settle so the first 0x96 is not sent into a
        USB interface that has just been re-claimed (see
        SETTLE_AFTER_CLAIM_MS). The command order and bytes match the
        driver's ACTIVATE_READ_AND_NOP / ENABLE_CHIP / QUERY_MCU / NOP /
        CHECK_FW_VER states one to one.
        """
        if settle_ms > 0:
            log(self.verbose, f"settle {settle_ms} ms after claim")
            time.sleep(settle_ms / 1000.0)
        self.nop()
        self.enable_chip()
        self.query_mcu()
        self.nop()
        try:
            log(self.verbose, f"firmware: {self.firmware_version()!r}")
        except (Timeout, ProtocolError) as exc:
            log(self.verbose, f"firmware query failed: {exc}")

    def close(self):
        try:
            self._usb_util.release_interface(self.dev, INTERFACE)
        except Exception:
            pass


def save_psk(path: str, psk: bytes):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    # atomic-ish write, root-only
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(psk)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Provision the 27c6:5F10 TLS-PSK without Windows.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true",
                    help="actually generate and write a new PSK (default: read-only)")
    ap.add_argument("--psk-file", default=DEFAULT_PSK_FILE,
                    help=f"where to save the raw 32-byte PSK (default: {DEFAULT_PSK_FILE})")
    ap.add_argument("--psk", metavar="HEX",
                    help="use this 32-byte hex PSK instead of a random one (implies --write)")
    ap.add_argument("--psk-from-file", metavar="PATH",
                    help="read the 32-byte PSK from PATH (e.g. the driver's "
                         "/var/lib/fprint/goodix-5f10/psk) and write it to the "
                         "sensor (implies --write)")
    ap.add_argument("--sealed-len", type=int, default=324,
                    help="length of the (ignored by the MCU) host-backup blob "
                         "in the write payload (default: 324)")
    ap.add_argument("--no-bringup", action="store_true",
                    help="skip the pre-TLS bring-up (if another process left the chip ready)")
    ap.add_argument("--settle-ms", type=int, default=SETTLE_AFTER_CLAIM_MS,
                    help=f"pause after claiming USB before the first command "
                         f"(default: {SETTLE_AFTER_CLAIM_MS}; 0 disables)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    verbose = args.verbose
    do_write = args.write or args.psk is not None or args.psk_from_file is not None

    dev = Goodix5F10(verbose=verbose)
    try:
        if not args.no_bringup:
            dev.bring_up(args.settle_ms)

        cur_flags, cur = dev.psk_read()
        if cur is None:
            print("Current PSK: none (MCU reported no provisioned PSK)")
        else:
            print(f"Current PSK hash (flags 0x{cur_flags:08x}): {cur.hex()}")

        if not do_write:
            psk_demo = bytes(32)
            blob = t.build_write_payload(psk_demo, sealed=bytes(args.sealed_len),
                                         seed=bytes(8))
            print()
            print("Dry run (read-only). It *would* generate a random 32-byte PSK,")
            print("write this payload with command 0xE0, then re-read 0xE4 and")
            print("compare against SHA256(TLV-1 body).")
            print(f"  payload length : {len(blob)} bytes")
            print(f"  host hash      : {t.host_hash(psk_demo).hex()}")
            if os.path.exists(args.psk_file):
                try:
                    with open(args.psk_file, "rb") as fh:
                        file_psk = fh.read(32)
                    if len(file_psk) == 32:
                        print(f"  file host hash : {t.host_hash(file_psk).hex()} "
                              f"({args.psk_file})")
                except OSError:
                    pass
            print("Re-run with --write to actually provision.")
            return 0

        if args.psk:
            psk = bytes.fromhex(args.psk)
            if len(psk) != 32:
                ap.error("--psk must be 32 bytes (64 hex chars)")
        elif args.psk_from_file:
            try:
                with open(args.psk_from_file, "rb") as fh:
                    psk = fh.read()
            except OSError as exc:
                ap.error(f"cannot read {args.psk_from_file}: {exc}")
            if len(psk) != 32:
                ap.error(f"--psk-from-file: expected 32 bytes, got {len(psk)} "
                         f"from {args.psk_from_file}")
        else:
            psk = secrets.token_bytes(32)

        blob = t.build_write_payload(psk, sealed=secrets.token_bytes(args.sealed_len),
                                     seed=secrets.token_bytes(8))
        want = t.host_hash(psk)
        if args.psk_from_file:
            source = f"{args.psk_from_file}"
        elif args.psk:
            source = "--psk"
        else:
            source = "random (token_bytes)"
        print(f"\nPSK source  : {source}")
        print(f"PSK ({len(psk)} bytes): {psk.hex()}")
        print(f"Host hash    : {want.hex()}")
        print("Writing (command 0xE0) ...")
        dev.psk_write(blob)

        # verify
        vflags, vdata = dev.psk_read()
        if vdata is None:
            print("ERROR: MCU reports no PSK after write.", file=sys.stderr)
            return 3
        print(f"Read back hash: {vdata.hex()}")
        if vflags != 0xBB020003 or vdata != want:
            print("ERROR: read-back does not match; NOT saving the PSK.",
                  file=sys.stderr)
            return 4

        save_psk(args.psk_file, psk)
        print(f"OK: verified and saved raw PSK to {args.psk_file}")
        return 0
    except Timeout as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("The sensor did not answer. Is fprintd stopped? Are you root? "
              "Is the PSK slot present? Re-run with -v.", file=sys.stderr)
        return 2
    finally:
        dev.close()


if __name__ == "__main__":
    sys.exit(main())
