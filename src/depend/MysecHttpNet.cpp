/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */


/*
 * MysecHttpNet.cpp
 *
 *  Created on: 23 de dez de 2016
 *      Author: user2
 */

#include "MysecHttpNet.h"
#include "MysecUtil.h"
#include "MysecDeviceState.h"

const char* headerKeys[] = {"token"};

MysecHttpNet::MysecHttpNet() {
  // TODO Auto-generated constructor stub

}

MysecHttpNet::~MysecHttpNet() {
  // TODO Auto-generated destructor stub
}

bool MysecHttpNet::getTime(HTTPClient &wc_http) {
  if (_mysecDeviceState.timeoffset == 0) { // se nunca pegou hora
    MYSECSWITCH_DEBUGF(("HttpNet getTime=%s\n"), _mysecDeviceState.url.c_str());
    if (wc_http.begin(_mysecDeviceState.url + F("/rest/time"))) {
      int result = wc_http.GET();
      MYSECSWITCH_DEBUGF(F("HttpNet getTime result=%d\n"), result);
      _mysecDeviceState.lasttimeMillis = millis(); // guarda o offset de millis
      if (result >= 0) {
        // valida retorno
        String resp = wc_http.getString();
        MYSECSWITCH_DEBUGF(F("HttpNet getTime resp=%s\n"), resp.c_str());
        wc_http.end();
        // obtém o timeoffset e ajusta conforme millis();
        //como millis() é 32 bits, como saber quando tiver overflow?
        _mysecDeviceState.timeoffset = MysecUtil::atoull(resp);
      } else {
        wc_http.end();
        return false;
      }
    }
  }
  return true;
}
int MysecHttpNet::request(String& uri, String &payload, String &response, HTTPClient &wc_http) {
  if (wc_http.begin(_mysecDeviceState.url + uri)) {
    int result = -1;
    {
      String token = MysecUtil::makeToken(payload.c_str(), _mysecDeviceState.passkey2);
      String auth;
      auth.reserve(52);
      auth.concat(F("Bearer "));
      auth.concat(token);
      wc_http.addHeader(F("Authorization"), auth);
      MYSECSWITCH_DEBUGF(F("HttpNet request url=%s, uri=%s, reqToken=%s\n"), _mysecDeviceState.url.c_str(), uri.c_str(), token.c_str());
      wc_http.addHeader(F("Content-Type"), F("application/json"));
      wc_http.addHeader(F("Accept"), F("application/json"));
      wc_http.addHeader(F("device"), MysecUtil::ulltoa(_mysecDeviceState.id));
      MYSECSWITCH_DEBUGF(F("HttpNet request Payload=%s\n"), payload.c_str());
      wc_http.collectHeaders(headerKeys, 1);
      result = wc_http.POST((uint8_t*)payload.c_str(), payload.length());
    }
    if (result >= 0) {
      // valida retorno
      response.remove(0);
      response.concat(wc_http.getString());
      String respToken = wc_http.header((size_t)0);
      wc_http.end();
      // agora processa a resposta e atualiza a estrutura
      // A resposta contém o próximo estado
      if (result == 200) {
        String respToken2 = MysecUtil::makeToken(response.c_str(), _mysecDeviceState.passkey2);
        MYSECSWITCH_DEBUGF(F("HttpNet request Response=%s\n"), response.c_str());
        MYSECSWITCH_DEBUGF(F("HttpNet request respToken=%s\n"), respToken.c_str());
        MYSECSWITCH_DEBUGF(F("HttpNet request gen respToken=%s\n"), respToken2.c_str());
        if (respToken == respToken2) {
          wc_http.end();
          return 0; // 0 ok
        }
        result = -999; // assinatura inválida
      }
    }
    MYSECSWITCH_DEBUGF(F("HttpNet request Retornou erro do servidor %d\n"), result);
    if (result != 429) {
      // ignora quando o erro for TooManyRequests
      _mysecDeviceState.timeoffset = 0; // será necessário obter novamente o timestamp
    }
    wc_http.end();
    return result;
  }
  wc_http.end();
  return 1; // 1 = erro
}
MysecHttpNet _mysecHttpNet;
