/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * BU64.h
 *
 *  Created on: 2 de set de 2016
 *      Author: user
 */

#ifndef BU64_H_
#define BU64_H_

#include <Arduino.h>
class BU64 {
private:
	static unsigned char reverse(char c);
public:
	static int encode(char *output, const uint8_t *input, int inputLen);
	static int encode(String& output, const uint8_t *input, int inputLen);
	static int decode(uint8_t * output, const char * input, int inputLen);
	static int encodedSize(int plainLen);
	static int decodedSize(char * input, int inputLen);
};

#endif /* BU64_H_ */
