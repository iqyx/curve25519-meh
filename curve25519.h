/**
 * A meh refactoring of TweetNaCl Curve25519.
 *
 * The original library was slightly obfuscated and hard to read. This is
 * the Curve25519 part required for ECDH computations extracted and refactored
 * from the code available at http://tweetnacl.cr.yp.to/20140427/tweetnacl.c
 *
 * (c) 2015, Marek Koza
 * CC0 public domain, http://creativecommons.org/publicdomain/zero/1.0/
 *
 * To the extent possible under law, the person who associated CC0 with this
 * work has waived all copyright and related or neighboring rights to this work.
 *
 *
 * Based on the TweetNaCl library by Daniel J. Bernstein, Bernard van Gastel,
 * Wesley Janssen, Tanja Lange, Peter Schwabe and Sjaak Smetsers placed into
 * a public domain. More information can be found at http://tweetnacl.cr.yp.to/.
 *
 */

#pragma once

#include <stdint.h>

/**
 * 256-bit integer in radix 2^16
 */
typedef int64_t gf[16];
#define CURVE25519_GF_SIZE 128

/**
 * Public key, private key and shared secret size (in bytes)
 */
#define CURVE25519_KEY_SIZE 32


void curve25519_scalarmult(
	uint8_t result[static CURVE25519_KEY_SIZE],
	const uint8_t priv_key[static CURVE25519_KEY_SIZE],
	const uint8_t basepoint[static CURVE25519_KEY_SIZE]
);

void curve25519_scalarmult_base(
	uint8_t result[const CURVE25519_KEY_SIZE],
	const uint8_t priv_key[const CURVE25519_KEY_SIZE]
);
