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

#include <stdint.h>
#include <string.h>

#include "curve25519.h"


static const uint8_t curve25519_basepoint[CURVE25519_KEY_SIZE] = {9};
static const gf _121665_2 = {0xDB41,1};


/**
 * Reduce mod 2^255 - 19, radix 2^16
 */
static void curve25519_car(gf o) {
	int64_t c;

	for (uint_fast8_t i = 0; i < 16; i++) {
		o[i] += (1LL << 16);
		c = o[i] >> 16;
		o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
		o[i] -= c << 16;
	}
}


/**
 * 256bit conditional swap
 */
static void curve25519_sel(gf p, gf q, uint_fast8_t b) {
	int64_t t;
	int64_t c = ~(b - 1);

	for (uint_fast8_t i = 0; i < 16; i++) {
		t = c & (p[i] ^ q[i]);
		p[i] ^= t;
		q[i] ^= t;
	}
}


/**
 * Freeze integer mod 2^255 - 19 and store
 */
static void curve25519_pack(uint8_t o[static CURVE25519_KEY_SIZE], const gf n) {
	gf t;
	memcpy(t, n, CURVE25519_GF_SIZE);

	curve25519_car(t);
	curve25519_car(t);
	curve25519_car(t);

	for (uint_fast8_t j = 0; j < 2; j++) {
		gf m;
		m[0] = t[0] - 0xffed;
		for(uint_fast8_t i = 1; i < 15; i++) {
			m[i] = t[i] - 0xffff - ((m[i-1] >> 16) & 1);
			m[i-1] &= 0xffff;
		}
		m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
		uint_fast8_t b = (m[15] >> 16) & 1;
		m[14] &= 0xffff;
		curve25519_sel(t, m, 1 - b);
	}

	for (uint_fast8_t i = 0; i < 16; i++) {
		o[2 * i] = t[i] & 0xff;
		o[2 * i + 1] = (uint8_t)(t[i] >> 8);
	}
}


/**
 * Load integer mod 2^255 - 19
 */
static void curve25519_unpack(gf o, const uint8_t n[static CURVE25519_KEY_SIZE]) {
	for (uint_fast8_t i = 0; i < 16; i++) {
		o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
	}
	o[15] &= 0x7fff;
}


/**
 * Add 256-bit integers, radix 2^16
 */
static void curve25519_add(gf o, const gf a, const gf b) {
	for (uint_fast8_t i = 0; i < 16; i++) {
		o[i] = a[i] + b[i];
	}
}


/**
 * Subtract 256-bit integers, radix 2^16
 */
static void curve25519_sub(gf o, const gf a, const gf b) {
	for (uint_fast8_t i = 0; i < 16; i++) {
		o[i] = a[i] - b[i];
	}
}


/**
 * Multiply mod 2^255-19, radix 2^16
 */
static void curve25519_mul(gf o, const gf a, const gf b) {
	int64_t t[31] = {0};

	for (uint_fast8_t i = 0; i < 16; i++) {
		for (uint_fast8_t j = 0; j < 16; j++) {
			t[i + j] += a[i] * b[j];
		}
	}

	for (uint_fast8_t i = 0; i < 15; i++) {
		t[i] += 38 * t[i + 16];
	}

	memcpy(o, t, CURVE25519_GF_SIZE);

	curve25519_car(o);
	curve25519_car(o);
}


/**
 * Square mod 2^255-19, radix 2^16
 */
static void curve25519_square(gf o, const gf a) {
	curve25519_mul(o, a, a);
}


/**
 * Power 2^255 - 21 mod 2^255 - 19
 */
static void curve25519_inv(gf o, const gf i) {
	gf c;
	memcpy(c, i, CURVE25519_GF_SIZE);

	for (int_fast16_t a = 253; a >= 0; a--) {
		curve25519_square(c, c);
		if (a != 2 && a != 4) {
			curve25519_mul(c, c, i);
		}
	}
	memcpy(o, c, CURVE25519_GF_SIZE);
}


void curve25519_scalarmult(
	uint8_t result[static CURVE25519_KEY_SIZE],
	const uint8_t priv_key[static CURVE25519_KEY_SIZE],
	const uint8_t basepoint[static CURVE25519_KEY_SIZE]
) {
	uint8_t priv_key_m[CURVE25519_KEY_SIZE];
	int64_t x[80];

	gf a, b, c, d, e, f;

	memcpy(priv_key_m, priv_key, 32);
	priv_key_m[31] = (priv_key[31] & 127) | 64;
	priv_key_m[0] &= 248;

	curve25519_unpack(x, basepoint);

	memset(a, 0, CURVE25519_GF_SIZE);
	memcpy(b, x, CURVE25519_GF_SIZE);
	memset(c, 0, CURVE25519_GF_SIZE);
	memset(d, 0, CURVE25519_GF_SIZE);
	a[0] = 1;
	d[0] = 1;

	for (int_fast16_t i = 254; i >= 0; i--) {

		uint_fast8_t r = (priv_key_m[i >> 3] >> (i & 7)) & 1;

		curve25519_sel(a, b, r);
		curve25519_sel(c, d, r);

		curve25519_add(e, a, c);
		curve25519_sub(a, a, c);
		curve25519_add(c, b, d);
		curve25519_sub(b, b, d);
		curve25519_square(d, e);
		curve25519_square(f, a);
		curve25519_mul(a, c, a);
		curve25519_mul(c, b, e);
		curve25519_add(e, a, c);
		curve25519_sub(a, a, c);
		curve25519_square(b, a);
		curve25519_sub(c, d, f);
		curve25519_mul(a, c, _121665_2);
		curve25519_add(a, a, d);
		curve25519_mul(c, c, a);
		curve25519_mul(a, d, f);
		curve25519_mul(d, b, x);
		curve25519_square(b, e);

		curve25519_sel(a, b, r);
		curve25519_sel(c, d, r);
	}

	memcpy(x + 16, a, CURVE25519_GF_SIZE);
	memcpy(x + 32, c, CURVE25519_GF_SIZE);
	memcpy(x + 48, b, CURVE25519_GF_SIZE);
	memcpy(x + 64, d, CURVE25519_GF_SIZE);

	curve25519_inv(x + 32, x + 32);
	curve25519_mul(x + 16, x + 16, x + 32);
	curve25519_pack(result, x + 16);
}


void curve25519_scalarmult_base(
	uint8_t result[static CURVE25519_KEY_SIZE],
	const uint8_t priv_key[static CURVE25519_KEY_SIZE]
) {
	curve25519_scalarmult(result, priv_key, curve25519_basepoint);
}

