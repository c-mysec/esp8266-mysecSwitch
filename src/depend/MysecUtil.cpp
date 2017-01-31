/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * MysecUtil.cpp
 *
 *  Created on: 23 de dez de 2016
 *      Author: user2
 */

#include <Arduino.h>
#include <ESP8266HTTPClient.h>
#include "BU64.h"
#include "sha256.h"
#include "MysecUtil.h"
#define LEAP_YEAR(Y) ( ((1970+Y)>0) && !((1970+Y)%4) && ( ((1970+Y)%100) || !((1970+Y)%400) ) )

String MysecUtil::ulltoa(uint64_t ll) {
  String a; a.reserve(20);
  uint64_t tid = ll;
  while (tid > 0) {
    uint8_t resto = tid % 10;
    a.concat((char)(resto + 48));
    tid = tid / 10;
  }
  String b; b.reserve(a.length());
  for (int i = a.length() - 1; i >= 0; i--) {
    b.concat(a.charAt(i));
  }
  return b;
}
uint64_t MysecUtil::atoull(const String& a) {
  uint64_t ll = 0;
  for (unsigned int i = 0; i < a.length(); i++) {
    ll = ll * 10 + (((int)a.charAt(i)) - 48);
  }
  return ll;
}
String MysecUtil::makeToken(const char* payload, const uint8_t * passkey2) {
  uint8_t *hash;
  String chaveOriginal; chaveOriginal.reserve(44);
  BU64::encode(chaveOriginal, passkey2, 32);
  Sha256.initHmac(passkey2, 32); // key, and length of key in bytes
  Sha256.print(payload);
  hash = Sha256.resultHmac(); // 32 bytes
  String bearer;
  bearer.reserve(45);
  BU64::encode(bearer, hash, 32);
  return bearer;
}
bool MysecUtil::validateToken(const char* payload, const char* receivedToken, const uint8_t * passkey2) {
  uint8_t *hash;
  String chaveOriginal; chaveOriginal.reserve(44);
  BU64::encode(chaveOriginal, passkey2, 32);
  Sha256.initHmac(passkey2, 32); // key, and length of key in bytes
  Sha256.print(payload);
  hash = Sha256.resultHmac(); // 32 bytes
  uint8_t hash2[32];
  BU64::decode(hash2, receivedToken, 44);
  String r; r.reserve(45);
  BU64::encode(r, hash, 32);
  MYSECSWITCH_DEBUGF(F("Util validateToken Payload: %s\nToken: %s\nCalc Token: %s\n"), payload, receivedToken, r.c_str());
  return (memcmp(hash, hash2, 32) == 0);
}


String MysecUtil::formatTime(uint64_t temp, long timezone, bool daylight) {
  uint8_t monthDays[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

  unsigned int mil = temp % 1000ull; temp /= 1000;

  if (daylight) // Sommerzeit beachten
    temp = temp + (timezone * 360) + 3600;
  else {
    temp = temp + (timezone * 360);
  }

  unsigned int s = temp % 60; temp /= 60;
  unsigned int m = temp % 60; temp /= 60;
  unsigned int h = temp % 24;

  temp /= 24; // contém dias

  unsigned int year = 0;
  unsigned int days = 0;
  while ((unsigned) (days += (LEAP_YEAR(year) ? 366 : 365)) <= temp) { // vai retirando os dias de cada ano desde 1970
    year++;
  }
  days -= LEAP_YEAR(year) ? 366 : 365; // tira do último ano
  temp -= days; // agora só restam os dias deste ano - now it is days in this year, starting at 0

  days = 0;
  unsigned int month = 0;
  unsigned int monthLength = 0;
  for (month = 0; month < 12; month++) {
    if (month == 1) { // february
      if (LEAP_YEAR(year)) {
        monthLength = 29;
      } else {
        monthLength = 28;
      }
    } else {
      monthLength = monthDays[month];
    }

    if (temp >= monthLength) {
      temp -= monthLength; // vai retirando os dias de cada mês
    } else {
      break; // até não ter dias suficientes para o mês
    }
  }
  String resp; resp.reserve(26);
  resp.concat(year + 1970);
  resp.concat('-');
  if (month < 9) resp.concat('0');
  resp.concat(month + 1); // month começa em 0
  resp.concat('-');
  if (temp < 9) resp.concat('0');
  resp.concat(((int)temp) + 1); // day também está começando em 0
  resp.concat(' ');
  if (h < 10) resp.concat('0');
  resp.concat(h);
  resp.concat(':');
  if (m < 10) resp.concat('0');
  resp.concat(m);
  resp.concat(':');
  if (s < 10) resp.concat('0');
  resp.concat(s);
  resp.concat('.');
  if (mil < 100) resp.concat('0');
  if (mil < 10) resp.concat('0');
  resp.concat(mil);
  return resp;
}



const char PM_TIME[] PROGMEM = {"time"};
const char PM_FASE[] PROGMEM = {"fase"};
const char PM_S[] PROGMEM = {"s"};
const char PM_FPINFLAG[] PROGMEM = {"fpinflag"};
const char PM_PINS[] PROGMEM = {"pins"};
const char PM_PINNUMBER[] PROGMEM = {"pinNumber"};
const char PM_NEWKEY[] PROGMEM = {"newkey"};
const char PM_TEMPOLIGADO[] PROGMEM = {"tempoLigado"};
const char PM_TEMPODESLIGADO[] PROGMEM = {"tempoDesligado"};
const char PM_TAG1[] PROGMEM = {"tag1"};
const char PM_TAG2[] PROGMEM = {"tag2"};

const char MYSECSWITCH_PM_DEBUG[] PROGMEM = {"DEBUG:MySec "};
const char MYSECSWITCH_PM_INFO[] PROGMEM = {"INFO:MySec "};
const char MYSECSWITCH_PM_ERROR[] PROGMEM = {"ERROR:MySec "};
