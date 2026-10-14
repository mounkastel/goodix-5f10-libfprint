/*
 * Goodix 5F10 TLS-PSK packing for libfprint.
 *
 * Fixed constant of the sensor protocol; identical on every host. It applies
 * to the 32-byte TLS PSK before handing it to the MCU. It is a pure function
 * of the key with static material; see
 * tools/goodix-5f10-provision/goodix_psk_tlv.py for the full description and
 * a byte-exact, independently validated Python twin.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include <glib.h>

#define GOODIX5F10_TLV1_BODY_LEN (102)
#define GOODIX5F10_PSK_HASH_LEN  (32)

/* The PSK slot as the MCU serves it on a 0xE4 read: flags 0xBB020003 with a
 * 32-byte SHA256(TLV-1 body). Must stay identical to GOODIX_5F10_PSK_FLAGS /
 * GOODIX_5F10_PSK_LEN from goodix5f10.h; they live here too so the read
 * decision below stays a pure function testable without the driver tree
 * (tests/test-goodix5f10-config.c asserts the equality). */
#define GOODIX5F10_PSK_SLOT_FLAGS (0xbb020003u)
#define GOODIX5F10_PSK_SLOT_LEN   (32)

/* Outcome of a 0xE4 preset-PSK read, decided without touching hardware. */
typedef enum {
  GOODIX5F10_PSK_MATCH,                  /* chip hash == host hash of stored key */
  GOODIX5F10_PSK_MISMATCH_AUTOPROVISION, /* hashes differ, env set: rewrite sensor */
  GOODIX5F10_PSK_MISMATCH_FAIL,          /* hashes differ, env unset: fail now */
  GOODIX5F10_PSK_MISSING,                /* success==FALSE: empty/unreadable slot */
  GOODIX5F10_PSK_REPLY_INVALID,          /* success but flags/length/shape unexpected */
  GOODIX5F10_PSK_IO_ERROR,               /* stored key could not be hashed */
} Goodix5f10PskDecision;

/* Decide what a 0xE4 reply means. Pure: no USB, no disk, no globals.
 * `chip_hash' (chip_len bytes) is the hash the sensor reported, `stored' the
 * 32-byte key from disk. Transport errors never reach here; the caller fails
 * those through before consulting the decision. */
Goodix5f10PskDecision
goodix5f10_psk_decide (gboolean success, guint32 flags, guint16 length,
                       const guint8 *chip_hash, gsize chip_len,
                       const guint8 stored[GOODIX5F10_PSK_HASH_LEN],
                       gboolean autoprovision);

/* Build the 102-byte TLV-1 body for a 32-byte PSK. */
void goodix5f10_psk_tlv1_body (const guint8 psk[32], guint8 out[GOODIX5F10_TLV1_BODY_LEN]);

/* SHA256 of the TLV-1 body: what the MCU returns for a 0xBB020003 read. */
gboolean goodix5f10_psk_host_hash (const guint8 psk[32], guint8 out[GOODIX5F10_PSK_HASH_LEN]);

/* Parse the GOODIX5F10_AUTOPROVISION opt-out. NULL (unset) and "1" mean
 * enabled; "0" disables; anything else warns and stays enabled. Pure apart
 * from the warning log. */
gboolean goodix5f10_autoprovision_enabled (const char *value);

/* 32 random bytes (system CSPRNG).  Caller frees. */
guint8 *goodix5f10_psk_random_psk (void);

/* Full command-0xE0 payload: the 4-aligned "TLV-2" blob.  `sealed_len` is the
 * length of the (MCU-ignored) host-backup section.  Caller frees. */
guint8 *goodix5f10_psk_build_write (const guint8 psk[32], gsize sealed_len,
                                    gsize *out_len);

/* Known-answer self test. Test vectors: see tests/ for the expected output. TRUE if all pass. */
gboolean goodix5f10_psk_selftest (void);
