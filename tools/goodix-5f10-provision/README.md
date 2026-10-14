# goodix-5f10-provision

Generate, pack, write and verify the Goodix `27c6:5F10` TLS-PSK from Linux.

The 5F10's TLS-PSK is not a factory secret. The host generates 32 random
bytes, wraps them and writes them to the MCU itself (command `0xE0`), keeping a
host copy for its own reuse. Fixed constant of the sensor protocol; identical on every host, so the whole flow runs anywhere. The driver does this
by default (opt out with `GOODIX5F10_AUTOPROVISION=0`); this directory is the
standalone version of the same thing, plus the reference implementation the
C code was checked against.

## Files

| file | what it is |
| --- | --- |
| `goodix_psk_tlv.py` | The packer. Pure Python, no Windows. This is the canonical, documented description of the format. |
| `goodix_5f10_provision.py` | Standalone CLI (pyusb): bring up the sensor, read the current PSK hash, optionally generate + write + verify a new PSK, and save it. |
| `test_goodix_psk_tlv.py` | Known-answer tests. Test vectors: see tests/ for the expected output. |

## The format

The packer turns the 32-byte PSK into a 102-byte "TLV-1 body":

```
body = HMAC(32) || LE16(0xFF02) || LE32(32) || IV(16) || CT(32) || TAG(16)

KDF48  = 58f013ee...  (48 bytes; static)
AES    = AES-256-GCM, key = KDF48[0:32], AAD = 522dc1f099567d07f47f37a32a84427d
HMAC   = HMAC-SHA256, key = KDF48[16:48]  over  LE16(0xFF02) || LE32(32) || CT || TAG
IV     = SHA256( LE16(0xFF02) || LE32(32) || PSK[0:8] || LE32(3) x 16 )[0:16]
```

That body is placed in the MCU payload as:

```
[0xBB010003][102][body]
```

and wrapped, together with a host-backup section, into the payload for command
`0xE0`:

```
[0xBB010002][sealed_len+8][sealed][seed(8)][0xBB010003][102][body]   (padded to 4)
```

`sealed` is the host's own backup. The MCU stores it
verbatim and never reads it; this tool writes random bytes of the same length.
Only the `0xBB010003` object matters.

The chip answers a `0xE4` read of flags `0xBB020003` with

```
[status=0x00][flags=0xBB020003][len=32][SHA256(body)]
```

which is the value the driver compares against. `goodix_psk_tlv.py` implements
both directions.

`KDF48` is a constant, not a machine key. Fixed constant of the sensor protocol; identical on every host.

## The CLI

Requires `pyusb` (and `libusb`), a Crypto backend, and root (or a udev rule).
Stop `fprintd` first.

```sh
# read-only: show the hash the sensor currently has
sudo ./goodix_5f10_provision.py

# generate, write, verify and save a new key
sudo ./goodix_5f10_provision.py --write \
     --psk-file /var/lib/fprint/goodix-5f10/psk

# write a specific key (also implies --write)
sudo ./goodix_5f10_provision.py --psk 00112233...ff
```

It mirrors the driver's pre-TLS bring-up (NOP, ENABLE_CHIP, QUERY_MCU, NOP,
firmware version, PSK read), then:

1. reads the current hash via `0xE4`;
2. generates 32 random bytes;
3. packs and writes them via `0xE0`;
4. reads `0xE4` again and requires it to equal `SHA256(TLV-1 body)`;
5. only then writes the raw key to `--psk-file`.

If step 4 fails the key is **not** saved and nothing else is touched.

## Safety

- The CLI does nothing to the sensor unless `--write` (or `--psk` /
  `--psk-from-file`) is given.
- The MCU PSK slot is rewritable; the Windows driver re-provisions on mismatch, so
  a write is not a one-shot fuse.
- There is no public 5F10 recovery image. Treat a write as a real change to the
  device, not a no-op.

## Testing without hardware

```sh
python test_goodix_psk_tlv.py          # packer test vectors: prints ALL_MATCH True
python test_goodix_5f10_provision.py   # CLI flow against a scripted "chip": 18 offline tests
```

The second one runs the tool's real transport logic (`command()`, `psk_read()`,
`psk_write()`, `bring_up()`, `main()`) against a fake wire that decodes the
actual USB frames, so the dry-run default, the write path (ack-only and full
reply answers) and the verify-failure path are all exercised without hardware.

The C twin of the packer (`libfprint/drivers/goodixtls/goodix5f10_psk.c`) carries
the same two test vectors in `goodix5f10_psk_selftest()`, which the driver runs at
open before generating a fresh key, and
`tests/test-goodix5f10-config.c` pins the 0xE0 payload layout.

### Compiling the C twin without the libfprint tree

`test_psk_c.c` builds the actual driver C file against real GLib + OpenSSL, so it
can be validated on any machine with that pair — including Windows via MSYS2
MinGW-w64 (verified with `mingw-w64-x86_64-gcc 16.1.0`, `glib2 2.88.1`,
`openssl 3.6.3`):

```sh
pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-glib2 \
             mingw-w64-x86_64-openssl mingw-w64-x86_64-pkgconf

export PATH=/mingw64/bin:/usr/bin:/bin
export PKG_CONFIG_PATH=/mingw64/lib/pkgconfig
cd tools/goodix-5f10-provision

gcc -o test_psk_c.exe test_psk_c.c \
    ../../libfprint/drivers/goodixtls/goodix5f10_psk.c \
    -I../../libfprint/drivers/goodixtls \
    $(pkg-config --cflags --libs glib-2.0) -lcrypto

./test_psk_c.exe     # expect PASS, zeros hash b5e0beeb94c84eb9...
```

Run from the MSYS2 shell (or `C:\msys64\usr\bin\bash.exe -lc '...'`), because the
MinGW `gcc` driver needs `/mingw64/bin` and `/usr/bin` on `PATH` to find `cc1`
and runtime DLLs.
