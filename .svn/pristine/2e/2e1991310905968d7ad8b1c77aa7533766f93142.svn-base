/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * BU64.cpp
 *
 *  Created on: 2 de set de 2016
 *      Author: user
 */

#include <Arduino.h>
#include "BU64.h"

const char characteres[] PROGMEM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";

int BU64::encode(char *output, const uint8_t *input, int inputLen) {
	int i = 0, j = 0;
	int encLen = 0;
	unsigned char a3[3];
	unsigned char a4[4];

	while(inputLen--) {
		a3[i++] = *(input++);
		if(i == 3) {
			a4[0] = (a3[0] & 0xfc) >> 2;
			a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
			a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
			a4[3] = (a3[2] & 0x3f);

			for(i = 0; i < 4; i++) {
				output[encLen++] = pgm_read_byte(&characteres[a4[i]]);
			}

			i = 0;
		}
	}

	if(i) {
		for(j = i; j < 3; j++) {
			a3[j] = '\0';
		}

		a4[0] = (a3[0] & 0xfc) >> 2;
		a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
		a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
		a4[3] = (a3[2] & 0x3f);

		for(j = 0; j < i + 1; j++) {
			output[encLen++] = pgm_read_byte(&characteres[a4[j]]);
		}

		while((i++ < 3)) {
			output[encLen++] = '=';
		}
	}
	output[encLen] = '\0';
	return encLen;
}
int BU64::encode(String &output, const uint8_t *input, int inputLen) {
	int i = 0, j = 0;
	int encLen = 0;
	unsigned char a3[3];
	unsigned char a4[4];

	while(inputLen--) {
		a3[i++] = *(input++);
		if(i == 3) {
			a4[0] = (a3[0] & 0xfc) >> 2;
			a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
			a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
			a4[3] = (a3[2] & 0x3f);

			for(i = 0; i < 4; i++) {
				output.concat((char) pgm_read_byte(&characteres[a4[i]]));
				encLen++;
			}
			i = 0;
		}
	}

	if(i) {
		for(j = i; j < 3; j++) {
			a3[j] = '\0';
		}

		a4[0] = (a3[0] & 0xfc) >> 2;
		a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
		a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
		a4[3] = (a3[2] & 0x3f);

		for(j = 0; j < i + 1; j++) {
			output.concat((char)pgm_read_byte(&characteres[a4[j]]));
			encLen++;
		}

		while((i++ < 3)) {
			output.concat('=');
			encLen++;
		}
	}
	return encLen;
}
int BU64::decode(uint8_t * output, const char * input, int inputLen) {
	int i = 0, j = 0;
	int decLen = 0;
	unsigned char a3[3];
	unsigned char a4[4];


	while (inputLen--) {
		if(*input == '=') {
			break;
		}

		a4[i++] = *(input++);
		if (i == 4) {
			for (i = 0; i <4; i++) {
				a4[i] = reverse(a4[i]);
			}

			a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
			a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
			a3[2] = ((a4[2] & 0x3) << 6) + a4[3];

			for (i = 0; i < 3; i++) {
				output[decLen++] = a3[i];
			}
			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; j++) {
			a4[j] = '\0';
		}

		for (j = 0; j <4; j++) {
			a4[j] = reverse(a4[j]);
		}

		a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
		a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
		a3[2] = ((a4[2] & 0x3) << 6) + a4[3];

		for (j = 0; j < i - 1; j++) {
			output[decLen++] = a3[j];
		}
	}
	//output[decLen] = '\0';
	return decLen;
}

int BU64::encodedSize(int plainLen) {
	int n = plainLen;
	return (n + 2 - ((n + 2) % 3)) / 3 * 4;
}

int BU64::decodedSize(char * input, int inputLen) {
	int i = 0;
	int numEq = 0;
	for(i = inputLen - 1; input[i] == '='; i--) {
		numEq++;
	}
	return ((6 * inputLen) / 8) - numEq;
}

unsigned char BU64::reverse(char c) {
	if(c >='A' && c <='Z') return c - 'A';
	if(c >='a' && c <='z') return c - 71;
	if(c >='0' && c <='9') return c + 4;
	if(c == '-') return 62;
	if(c == '_') return 63;
	return -1;
}
