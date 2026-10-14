/*
 * Standalone compile check for the driver's PSK packer.  Compiles
 * ../../libfprint/drivers/goodixtls/goodix5f10_psk.c against real GLib +
 * OpenSSL and verifies:
 *   - goodix5f10_psk_selftest(): both test vectors
 *   - the 0xE0 write payload layout for a zeros PSK (452 bytes, 4-aligned,
 *     exact head/tail fields)
 *
 * This is the same coverage as tests/test-goodix5f10-config.c but needs no
 * libfprint tree, so it can be built anywhere GLib and OpenSSL exist:
 *
 *   cc -o test_psk_c test_psk_c.c \
 *      ../../libfprint/drivers/goodixtls/goodix5f10_psk.c \
 *      -I../../libfprint/drivers/goodixtls \
 *      $(pkg-config --cflags --libs glib-2.0) -lcrypto
 *
 * Prints PASS or FAIL; exit code reflects it.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <stdio.h>
#include <string.h>

#include "goodix5f10_psk.h"

#define PSK_LEN (32)

static void
print_hex (const guint8 *b, gsize n)
{
  for (gsize i = 0; i < n; i++)
    printf ("%02x", b[i]);
}

static guint32
le32_at (const guint8 *p)
{
  return (guint32) p[0] | (guint32) p[1] << 8 | (guint32) p[2] << 16
         | (guint32) p[3] << 24;
}

static int
fail (const char *what)
{
  printf ("FAIL: %s\n", what);
  return 1;
}

int
main (void)
{
  const guint8 zeros[PSK_LEN] = { 0 };
  guint8 want[GOODIX5F10_PSK_HASH_LEN];
  g_autofree guint8 *blob = NULL;
  g_autofree guint8 *body_ref = NULL;
  gsize len = 0;
  const guint8 *body;

  /* The zeros-PSK host hash, pinned by the test vectors. */
  if (!goodix5f10_psk_host_hash (zeros, want))
    return fail ("host_hash returned error");
  printf ("zeros host hash : ");
  print_hex (want, GOODIX5F10_PSK_HASH_LEN);
  printf ("\n");

  /* Self test covers both test vectors. */
  if (!goodix5f10_psk_selftest ())
    return fail ("selftest did not pass (zero or 0..31 vector)");
  printf ("selftest        : PASS (zero + 0..31 vectors)\n");

  /* Write payload layout for the zeros key. */
  blob = goodix5f10_psk_build_write (zeros, 324, &len);
  if (blob == NULL)
    return fail ("build_write returned NULL");
  if (len != 452 || len % 4 != 0)
    return fail ("write payload size");
  if (le32_at (blob) != 0xbb010002u || le32_at (blob + 4) != 324 + 8)
    return fail ("TLV-2 head");

  body = blob + 16 + 324; /* tag2(4) + len(4) + sealed(324) + seed(8) */
  if (le32_at (body) != 0xbb010003u || le32_at (body + 4) != GOODIX5F10_TLV1_BODY_LEN)
    return fail ("TLV-1 head");

  printf ("write payload   : len=452 layout ok\n");

  /* The embedded body must be exactly tlv1_body(zeros). */
  body_ref = g_malloc (GOODIX5F10_TLV1_BODY_LEN);
  goodix5f10_psk_tlv1_body (zeros, body_ref);
  if (memcmp (body + 8, body_ref, GOODIX5F10_TLV1_BODY_LEN) != 0)
    return fail ("embedded body != tlv1_body");

  printf ("embedded body   : matches tlv1_body\n");
  printf ("PASS\n");
  fflush (stdout);
  return 0;
}