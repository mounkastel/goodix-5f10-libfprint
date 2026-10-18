/*
 * Goodix 5F10 config table unit tests
 * Copyright (C) 2026 libfprint contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <glib.h>
#include <string.h>

#include "drivers/goodixtls/goodix5f10.h"
#include "drivers/goodixtls/goodix5f10_psk.h"

/* The table the sensor in this laptop runs, captured off the vendor exchange. Patching the
 * shipped template with this unit's OTP bytes has to land on it byte for byte, checksum
 * included -- that is the whole claim about how the three per-unit entries are derived. */
static const guint8 dev_config[] = {
  0x30, 0x11, 0x64, 0x75, 0x00, 0x75, 0x2c, 0xa1, 0x1c, 0xbd, 0x18, 0xd5,
  0x00, 0xd5, 0x00, 0xd5, 0x00, 0xba, 0x00, 0x00, 0x80, 0xca, 0x00, 0x06,
  0x00, 0x84, 0x00, 0xbe, 0xb2, 0x86, 0x00, 0xc5, 0xb9, 0x88, 0x00, 0xb5,
  0xad, 0x8a, 0x00, 0x9d, 0x95, 0x8c, 0x00, 0x00, 0xbe, 0x8e, 0x00, 0x00,
  0xc5, 0x90, 0x00, 0x00, 0xb5, 0x92, 0x00, 0x00, 0x9d, 0x94, 0x00, 0x00,
  0xaf, 0x96, 0x00, 0x00, 0xbf, 0x98, 0x00, 0x00, 0xb6, 0x9a, 0x00, 0x00,
  0xa7, 0xd2, 0x00, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x00, 0xd6, 0x00, 0x00,
  0x00, 0xd8, 0x00, 0x00, 0x00, 0x12, 0x00, 0x03, 0x04, 0xd0, 0x00, 0x00,
  0x00, 0x70, 0x00, 0x00, 0x00, 0x72, 0x00, 0x78, 0x56, 0x74, 0x00, 0x34,
  0x12, 0x20, 0x00, 0x10, 0x40, 0x20, 0x02, 0xa8, 0x02, 0x2a, 0x01, 0x82,
  0x03, 0x22, 0x00, 0x01, 0x20, 0x24, 0x00, 0x14, 0x00, 0x80, 0x00, 0x01,
  0x04, 0x5c, 0x00, 0x00, 0x01, 0x56, 0x00, 0x0c, 0x24, 0x58, 0x00, 0x05,
  0x00, 0x32, 0x00, 0x08, 0x02, 0x66, 0x00, 0x00, 0x02, 0x7c, 0x00, 0x00,
  0x38, 0x82, 0x00, 0x80, 0x19, 0x2a, 0x01, 0x08, 0x00, 0x5c, 0x00, 0x80,
  0x00, 0x54, 0x00, 0x00, 0x01, 0x62, 0x00, 0x38, 0x04, 0x64, 0x00, 0x10,
  0x00, 0x66, 0x00, 0x00, 0x02, 0x7c, 0x00, 0x01, 0x38, 0x2a, 0x01, 0x08,
  0x00, 0x5c, 0x00, 0x00, 0x01, 0x52, 0x00, 0x08, 0x00, 0x54, 0x00, 0x00,
  0x01, 0x66, 0x00, 0x00, 0x02, 0x7c, 0x00, 0x01, 0x38, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xcb, 0xfd};

/* Deliberately not the driver's own reader: a copy of the code under test would agree with
 * it however wrong both are. */
static guint16
entry_value (const guint8 *config, guint section, guint16 tag)
{
  const guint base = config[1 + 2 * section];
  const guint end = base + config[2 + 2 * section];

  for (guint entry = base; entry + 4 <= end; entry += 4)
    if ((config[entry] | (guint16) config[entry + 1] << 8) == tag)
      return config[entry + 2] | (guint16) config[entry + 3] << 8;

  g_error ("no tag 0x%04x in section %u", tag, section);
}

static guint16
table_checksum (const guint8 *config, gsize len)
{
  guint32 sum = 0xa5a5;

  for (gsize i = 0; i + 2 < len; i += 2)
    sum = (sum + (config[i] | (guint16) config[i + 1] << 8)) & 0xffff;

  return 0x10000 - sum;
}

static void
test_config_this_unit (void)
{
  g_autofree guint8 *config = NULL;
  const guint8 *template;
  gsize len;

  template = goodix5f10_config_template (&len);
  g_assert_cmpuint (len, ==, sizeof (dev_config));
  config = g_memdup2 (template, len);

  goodix5f10_config_patch_from_otp (config, len, GOODIX5F10_DEV_DAC, GOODIX5F10_DEV_TCODE);
  g_assert_cmpmem (config, len, dev_config, sizeof (dev_config));
}

/* The FMI-76 from github issue #1 reports DAC 0x3c and TCODE 0xf9. Nothing here has been
 * seen on that sensor -- it is the arithmetic pinned down so a later capture can disagree
 * with it. */
static void
test_config_other_unit (void)
{
  g_autofree guint8 *config = NULL;
  const guint8 *template;
  gsize len;

  template = goodix5f10_config_template (&len);
  config = g_memdup2 (template, len);

  goodix5f10_config_patch_from_otp (config, len, 0x3c, 0xf9);
  g_assert_cmphex (entry_value (config, 0, 0x0220), ==, 0x03c8);
  g_assert_cmphex (entry_value (config, 4, 0x005c), ==, 0x0100);
  g_assert_cmphex (entry_value (config, 2, 0x0082), ==, 0x1680);

  /* Tag 0x005c also sits in sections 2 and 3 and neither is calibration, so both have to
   * come out of the patch untouched. */
  g_assert_cmphex (entry_value (config, 2, 0x005c), ==, 0x0100);
  g_assert_cmphex (entry_value (config, 3, 0x005c), ==, 0x0080);

  g_assert_cmphex (table_checksum (config, len), ==,
                   (config[len - 2] | (guint16) config[len - 1] << 8));
}

static guint32
le32_at (const guint8 *p)
{
  return (guint32) p[0] | (guint32) p[1] << 8 | (guint32) p[2] << 16
         | (guint32) p[3] << 24;
}

/* The 0xE0 write payload for a zeros PSK must come out structurally exact: tag2,
 * sealed+8 length, the 324-byte sealed blob, 8-byte seed, then tag1 with the
 * 102-byte TLV-1 body, padded to a multiple of 4 (452 here). */
static void
test_psk_packer (void)
{
  const guint8 psk[32] = { 0 };
  g_autofree guint8 *blob = NULL;
  g_autofree guint8 *body_ref = NULL;
  guint8 want[GOODIX5F10_PSK_HASH_LEN];
  gsize len = 0;
  const guint8 *body_embedded;

  g_assert_true (goodix5f10_psk_selftest ());

  blob = goodix5f10_psk_build_write (psk, 324, &len);
  g_assert_nonnull (blob);
  g_assert_cmpuint (len, ==, 452);
  g_assert_cmpuint (len % 4, ==, 0);

  g_assert_cmphex (le32_at (blob), ==, 0xbb010002);
  g_assert_cmphex (le32_at (blob + 4), ==, 324 + 8);

  body_embedded = blob + 16 + 324; /* tag2(4) + len(4) + sealed(324) + seed(8) */
  g_assert_cmphex (le32_at (body_embedded), ==, 0xbb010003);
  g_assert_cmphex (le32_at (body_embedded + 4), ==, GOODIX5F10_TLV1_BODY_LEN);
  body_embedded += 8;

  /* The embedded body must be exactly the TLV-1 transformation of the key,
   * and the host hash the chip must answer with is SHA256 of that body. The
   * expected values below are derived from this implementation; the
   * real-device confirmation is that the chip accepted the write and the
   * read-back hash matched. */
  body_ref = g_malloc (GOODIX5F10_TLV1_BODY_LEN);
  g_assert_true (goodix5f10_psk_tlv1_body (psk, body_ref));
  g_assert_cmpmem (body_embedded, GOODIX5F10_TLV1_BODY_LEN, body_ref,
                   GOODIX5F10_TLV1_BODY_LEN);

  g_assert_true (goodix5f10_psk_host_hash (psk, want));
  g_assert_cmpuint (want[GOODIX5F10_PSK_HASH_LEN - 1], ==, 0x89); /* zeros vector 0x...c389 */
}

/* The GOODIX5F10_AUTOPROVISION opt-in: only "1" enables, NULL (unset) and
 * exactly "0" stay off, anything else warns once and stays off. */
static void
test_autoprovision_enabled (void)
{
  g_assert_false (goodix5f10_autoprovision_enabled (NULL));
  g_assert_true (goodix5f10_autoprovision_enabled ("1"));
  g_assert_false (goodix5f10_autoprovision_enabled ("0"));

  /* Weird values warn (same log domain the helper logs to) but stay off. */
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                         "*GOODIX5F10_AUTOPROVISION*");
  g_assert_false (goodix5f10_autoprovision_enabled ("banana"));
  g_test_assert_expected_messages ();

  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
                         "*GOODIX5F10_AUTOPROVISION*");
  g_assert_false (goodix5f10_autoprovision_enabled (""));
  g_test_assert_expected_messages ();
}

/* The 0xE4 read decision, branch by branch, with no device involved. The
 * expected hash values are derived from this implementation; the real-device
 * confirmation is that the chip accepted the write and the read-back hash
 * matched. */
static void
test_psk_decide (void)
{
  const guint8 zeros[GOODIX5F10_PSK_HASH_LEN] = { 0 };
  guint8 zeros_hash[GOODIX5F10_PSK_HASH_LEN];
  guint8 other[GOODIX5F10_PSK_HASH_LEN];

  /* The helper's slot constants must stay identical to the driver's own. */
  g_assert_cmphex (GOODIX5F10_PSK_SLOT_FLAGS, ==, GOODIX_5F10_PSK_FLAGS);
  g_assert_cmpuint (GOODIX5F10_PSK_SLOT_LEN, ==, GOODIX_5F10_PSK_LEN);

  g_assert_true (goodix5f10_psk_host_hash (zeros, zeros_hash));
  g_assert_cmphex (zeros_hash[0], ==, 0xb5);
  g_assert_cmphex (zeros_hash[1], ==, 0xe0);
  memset (other, 0x7c, sizeof (other));

  /* Match: the env setting is irrelevant, activation must continue. */
  g_assert_cmpint (goodix5f10_psk_decide (TRUE, GOODIX_5F10_PSK_FLAGS,
                                          GOODIX_5F10_PSK_LEN,
                                          zeros_hash, sizeof (zeros_hash),
                                          zeros, FALSE),
                   ==, GOODIX5F10_PSK_MATCH);
  g_assert_cmpint (goodix5f10_psk_decide (TRUE, GOODIX_5F10_PSK_FLAGS,
                                          GOODIX_5F10_PSK_LEN,
                                          zeros_hash, sizeof (zeros_hash),
                                          zeros, TRUE),
                   ==, GOODIX5F10_PSK_MATCH);

  /* Mismatch: provisioning-on picks rewrite, provisioning-off fails now
   * (fail-now must not continue). */
  g_assert_cmpint (goodix5f10_psk_decide (TRUE, GOODIX_5F10_PSK_FLAGS,
                                          GOODIX_5F10_PSK_LEN,
                                          other, sizeof (other),
                                          zeros, FALSE),
                   ==, GOODIX5F10_PSK_MISMATCH_FAIL);
  g_assert_cmpint (goodix5f10_psk_decide (TRUE, GOODIX_5F10_PSK_FLAGS,
                                          GOODIX_5F10_PSK_LEN,
                                          other, sizeof (other),
                                          zeros, TRUE),
                   ==, GOODIX5F10_PSK_MISMATCH_AUTOPROVISION);

  /* Missing slot (chip refused the read): same outcome either way, the
   * caller provisions when opted in and fails otherwise. */
  g_assert_cmpint (goodix5f10_psk_decide (FALSE, 0, 0, NULL, 0,
                                          zeros, FALSE),
                   ==, GOODIX5F10_PSK_MISSING);
  g_assert_cmpint (goodix5f10_psk_decide (FALSE, GOODIX_5F10_PSK_FLAGS,
                                          GOODIX_5F10_PSK_LEN, NULL, 0,
                                          zeros, TRUE),
                   ==, GOODIX5F10_PSK_MISSING);

  /* Well-formed success carrying the wrong shape is never a match. */
  g_assert_cmpint (goodix5f10_psk_decide (TRUE, 0xbb010003u,
                                          GOODIX_5F10_PSK_LEN,
                                          zeros_hash, sizeof (zeros_hash),
                                          zeros, FALSE),
                   ==, GOODIX5F10_PSK_REPLY_INVALID);
  g_assert_cmpint (goodix5f10_psk_decide (TRUE, GOODIX_5F10_PSK_FLAGS, 16,
                                          zeros_hash, 16,
                                          zeros, FALSE),
                   ==, GOODIX5F10_PSK_REPLY_INVALID);
  g_assert_cmpint (goodix5f10_psk_decide (TRUE, GOODIX_5F10_PSK_FLAGS,
                                          GOODIX_5F10_PSK_LEN, NULL, 0,
                                          zeros, FALSE),
                   ==, GOODIX5F10_PSK_REPLY_INVALID);
}

int
main (int argc, char *argv[])
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/goodix5f10/config/this-unit", test_config_this_unit);
  g_test_add_func ("/goodix5f10/config/other-unit", test_config_other_unit);
  g_test_add_func ("/goodix5f10/psk/packer", test_psk_packer);
  g_test_add_func ("/goodix5f10/psk/decide", test_psk_decide);
  g_test_add_func ("/goodix5f10/psk/autoprovision-enabled",
                   test_autoprovision_enabled);

  return g_test_run ();
}
