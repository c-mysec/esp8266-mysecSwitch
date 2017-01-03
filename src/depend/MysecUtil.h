/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * MysecUtil.h
 *
 *  Created on: 23 de dez de 2016
 *      Author: user2
 */

#ifndef MYSECUTIL_H_
#define MYSECUTIL_H_

#define MYSECSWITCH_DEBUG

#ifdef MYSECSWITCH_DEBUG
  #define MYSECSWITCH_DEBUGLN(buff) Serial.print(F("DEBUG:["));Serial.print(__PRETTY_FUNCTION__);Serial.print(F("] "));Serial.println(buff);
  #define MYSECSWITCH_DEBUGF2(fmt,...) Serial.print(F("DEBUG:["));Serial.print(__PRETTY_FUNCTION__);Serial.print(F("] "));Serial.printf(String(fmt).c_str(), __VA_ARGS__ )
#else
  #define MYSECSWITCH_DEBUGLN(buff)
  #define MYSECSWITCH_DEBUGF2(fmt,...)
#endif

#define JFS(x) JsonObjectKey(FPSTR(x))


extern const char PM_TIME[] PROGMEM;
extern const char PM_FASE[] PROGMEM;
extern const char PM_S[] PROGMEM;
extern const char PM_FPINFLAG[] PROGMEM;
extern const char PM_PINS[] PROGMEM;
extern const char PM_PINNUMBER[] PROGMEM;
extern const char PM_NEWKEY[] PROGMEM;
extern const char PM_TEMPOLIGADO[] PROGMEM;
extern const char PM_TEMPODESLIGADO[] PROGMEM;
extern const char PM_TAG1[] PROGMEM;
extern const char PM_TAG2[] PROGMEM;

class MysecUtil {
public:
  static String ulltoa(uint64_t ll);
  static uint64_t atoull(const String& a);
  static String formatTime(uint64_t temp);
  /* Devolve token BU64 */
  static String makeToken(const char* payload, const uint8_t * passkey2);
  /* receivedToken é BU64 */
  static bool validateToken(const char* payload, const char* receivedToken, const uint8_t * passkey2);

  //TODO: Falta mover criação de chaves para ca.
};

#endif /* MYSECUTIL_H_ */
