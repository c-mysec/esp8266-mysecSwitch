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

#ifndef MYSECSWITCH_DEBUG
#define MYSECSWITCH_DEBUG 3
#endif

extern const char MYSECSWITCH_PM_DEBUG[] PROGMEM;
extern const char MYSECSWITCH_PM_INFO[] PROGMEM;
extern const char MYSECSWITCH_PM_ERROR[] PROGMEM;
extern int __mysec_debug_mode;

#if MYSECSWITCH_DEBUG>2
  #define MYSECSWITCH_DEBUGLN(buff) if (__mysec_debug_mode>2) {Serial.print(FPSTR(MYSECSWITCH_PM_DEBUG));Serial.println(buff);}
  #define MYSECSWITCH_DEBUGF(fmt,...) if (__mysec_debug_mode>2) {Serial.print(FPSTR(MYSECSWITCH_PM_DEBUG));Serial.printf(String(fmt).c_str(), __VA_ARGS__ );}
#else
  #define MYSECSWITCH_DEBUGLN(buff)
  #define MYSECSWITCH_DEBUGF(fmt,...)
#endif
#if MYSECSWITCH_DEBUG>1
  #define MYSECSWITCH_INFOLN(buff) if (__mysec_debug_mode>1) {Serial.print(FPSTR(MYSECSWITCH_PM_INFO));Serial.println(buff);}
  #define MYSECSWITCH_INFOF(fmt,...) if (__mysec_debug_mode>1) {Serial.print(FPSTR(MYSECSWITCH_PM_INFO));Serial.printf(String(fmt).c_str(), __VA_ARGS__ );}
#else
  #define MYSECSWITCH_INFOLN(buff)
  #define MYSECSWITCH_INFOF(fmt,...)
#endif
#if MYSECSWITCH_DEBUG>0
  #define MYSECSWITCH_ERRORLN(buff) if (__mysec_debug_mode>0) {Serial.print(FPSTR(MYSECSWITCH_PM_ERROR));Serial.println(buff);}
  #define MYSECSWITCH_ERRORF(fmt,...) if (__mysec_debug_mode>0) {Serial.print(FPSTR(MYSECSWITCH_PM_ERROR));Serial.printf(String(fmt).c_str(), __VA_ARGS__ );}
#else
  #define MYSECSWITCH_ERRORLN(buff)
  #define MYSECSWITCH_ERRORF(fmt,...)
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
extern const char PM_DESAFIO1[] PROGMEM;
extern const char PM_DESAFIO2[] PROGMEM;
extern const char PM_DESAFIO3[] PROGMEM;
extern const char PM_DESAFIO4[] PROGMEM;

extern const char __PM_PVER[] PROGMEM;
extern const char __PM_PVERLABEL[] PROGMEM;
extern const char __PM_PLIBVERLABEL[] PROGMEM;
extern const char __PM_IDLABEL[] PROGMEM;



class MysecUtil {
public:
  static String ulltoa(uint64_t ll);
  static uint64_t atoull(const String& a);
  static String formatTime(uint64_t temp, long timezone, bool daylight);
  /* Devolve token BU64 */
  static String makeToken(const char* payload, const uint8_t * passkey2);
  /* receivedToken é BU64 */
  static bool validateToken(const char* payload, const char* receivedToken, const uint8_t * passkey2);
  static void setBit(uint8_t &value, uint8_t bit, bool active);
  static bool getBit(uint8_t value, uint8_t bit);

  //TODO: Falta mover criação de chaves para ca.
};

#endif /* MYSECUTIL_H_ */
