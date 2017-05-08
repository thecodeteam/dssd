/*
 * Copyright 2017 Dell Inc. or its subsidiaries.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <utf.h>

/*
 * The UTF-8 encoding represents any Unicode character from U+0000 to U+10FFFF
 * (the defined limit) as a sequence of 1-4 bytes using a Huffman-like coding:
 *
 * ------------------+---------------------------------------------
 * 00000000-0000007F | 0xxxxxxx
 * 00000080-000007FF | 110xxxxx 10xxxxxx
 * 00000800-0000FFFF | 1110xxxx 10xxxxxx 10xxxxxx
 * 00010000-0010FFFF | 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
 * ------------------+---------------------------------------------
 */

static const uint32_t utf8_max[5] = { 0, 0x7F, 0x7FF, 0xFFFF, 0x10FFFF };
static const uint8_t utf8_tag[6] = { 0x80, 0x00, 0xC0, 0xE0, 0xF0, 0xF8 };
static const uint8_t utf8_mask[6] = { 0x3F, 0x7F, 0x1F, 0x0F, 0x07, 0x03 };
static const int8_t utf8_shift[6] = { 6, 7, 5, 4, 3, 2 };

static const uint32_t unicode_sp_base = 0x10000;
static const uint32_t unicode_sp_shift = 10;
static const uint32_t unicode_sp_mask = 0x3FF;
static const uint32_t unicode_sp1_start = 0xD800;
static const uint32_t unicode_sp1_end = 0xDBFF;
static const uint32_t unicode_sp2_start = 0xDC00;
static const uint32_t unicode_sp2_end = 0xDFFF;

int
unicode_is_sp(uint32_t u)
{
	return (u >= unicode_sp_base);
}

int
unicode_is_sp1(uint32_t u1)
{
	return (u1 >= unicode_sp1_start && u1 <= unicode_sp1_end);
}

int
unicode_is_sp2(uint32_t u2)
{
	return (u2 >= unicode_sp2_start && u2 <= unicode_sp2_end);
}

void
unicode_to_sp(uint32_t u, uint32_t *u1, uint32_t *u2)
{
	u -= unicode_sp_base;

	*u1 = unicode_sp1_start + (u >> unicode_sp_shift);
	*u2 = unicode_sp2_start + (u & unicode_sp_mask);
}

uint32_t
unicode_from_sp(uint32_t u1, uint32_t u2)
{
	u1 -= unicode_sp1_start;
	u2 -= unicode_sp2_start;

	return (unicode_sp_base + (u1 << unicode_sp_shift) + u2);
}

char *
unicode_to_utf8_n(uint32_t u, char *s, int n)
{
	for (int i = n - 1; i != 0; i--) {
		s[i] = (u & utf8_mask[0]) | utf8_tag[0];
		u >>= utf8_shift[0];
	}

	s[0] = (char)(u + utf8_tag[n]);

	return (s + n);
}

const char *
unicode_from_utf8_n(uint32_t *u, const char *s, int n)
{
	uint32_t u1, c;
	uint32_t ux = 0;

	for (u1 = (uint8_t)*s++ - utf8_tag[n--]; n; n--) {
		c = (uint8_t)*s++ - utf8_tag[0];
		u1 = (u1 << utf8_shift[0]) ^ c;
		ux |= c;
	}

	*u = u1;

	return (ux > utf8_mask[0] ? NULL : s);
}

char *
unicode_to_utf8(uint32_t u, char *s)
{
	if (u <= utf8_max[1]) {
		return (unicode_to_utf8_n(u, s, 1));
	} else if (u <= utf8_max[2]) {
		return (unicode_to_utf8_n(u, s, 2));
	} else if (u <= utf8_max[3]) {
		return (unicode_to_utf8_n(u, s, 3));
	} else if (u <= utf8_max[4]) {
		return (unicode_to_utf8_n(u, s, 4));
	}
	return (NULL);
}

const char *
unicode_from_utf8(uint32_t *u, const char *s)
{
	uint8_t c = (uint8_t)*s;

	if (c < utf8_tag[0]) {
		return (unicode_from_utf8_n(u, s, 1));
	} else if (c < utf8_tag[2]) {
		return (NULL);
	} else if (c < utf8_tag[3]) {
		return (unicode_from_utf8_n(u, s, 2));
	} else if (c < utf8_tag[4]) {
		return (unicode_from_utf8_n(u, s, 3));
	} else if (c < utf8_tag[5]) {
		s = unicode_from_utf8_n(u, s, 4);
		if (*u <= utf8_max[4])
			return (s);
	}
	return (NULL);
}
