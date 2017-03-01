/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * MySecParser.h
 *
 *  Created on: 23 de dez de 2016
 *      Author: user2
 */

#ifndef MYSECPARSER_H_
#define MYSECPARSER_H_
#include <ArduinoJson.h>

class MysecParser {
public:
  MysecParser() {}
  virtual ~MysecParser() {}
  virtual String makePayload(uint32_t m, int fase, bool sendNextPb1);
  virtual String makePayloadH();
  String makeUrlRequest(uint32_t m);
  bool decodeResponseNewKeyTime(JsonObject& rdata, uint32_t m);
  virtual bool decodeResponse(const String& msgid, const String &resp, uint32_t m);
  bool decodeResponse2(JsonObject& rdata, uint32_t m);
};
#endif /* MYSECPARSER_H_ */
