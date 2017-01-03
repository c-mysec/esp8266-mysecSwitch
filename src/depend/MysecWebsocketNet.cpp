/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * MySecWebsocketNet.cpp
 *
 *  Created on: 23 de dez de 2016
 *      Author: user2
 */

#include "MysecWebsocketNet.h"
#include <ArduinoJson.h>
#include <WebSocketsClient.h>
#include "MysecDeviceState.h"
#include "MysecUtil.h"
#include "MysecParser.h"
#include "MysecHttpNet.h"
#include "MysecUdpNet.h"
WebSocketsClient webSocket;
void webSocketEvent(WStype_t type, uint8_t * payload, size_t lenght);

MysecWebsocketNet::MysecWebsocketNet() {
  // TODO Auto-generated constructor stub

}

MysecWebsocketNet::~MysecWebsocketNet() {
  // TODO Auto-generated destructor stub
}
// se retornar true então muda de estado
//_mysecDeviceState.state = MysecDeviceState::STATE_CONNECTING;
//
bool MysecWebsocketNet::connect(bool wssecure, const char* wshost, int wsport, const char* wsuri) {
  resp.remove(0);
  if (wssecure) {
    MYSECSWITCH_DEBUGF2(F("Iniciando websocket: wss://%s:%d%s\n"), wshost, wsport, wsuri);
    webSocket.beginSSL(wshost, wsport, wsuri);
  } else {
    MYSECSWITCH_DEBUGF2(F("Iniciando websocket: ws://%s:%d%s\n"), wshost, wsport, wsuri);
    webSocket.begin(wshost, wsport, wsuri);
  }
  webSocket.onEvent(webSocketEvent);
  return true;
}
void MysecWebsocketNet::loop() {
  webSocket.loop();
  // temos mensagem para processar
  if (resp.length() > 0) {
    // valida assinatura token.
    int pos = resp.indexOf(':'); // RSYNC:
    int pos2 = resp.indexOf(':', pos + 1); // TOKEN:
    String msgid = resp.substring(0, pos);
    String respToken = resp.substring(pos + 1, pos2);
    String response = resp.substring(pos2 + 1); // pula ':'
    resp.remove(0);
    String respToken2 = MysecUtil::makeToken(response.c_str(), _mysecDeviceState.passkey2);
    MYSECSWITCH_DEBUGF2(F("Response=%s\n"), response.c_str());
    MYSECSWITCH_DEBUGF2(F("respToken=%s\n"), respToken.c_str());
    MYSECSWITCH_DEBUGF2(F("gen respToken=%s\n"), respToken2.c_str());
    if (respToken == respToken2) {
      bool r = _mysecDeviceState.mysecParser->decodeResponse(msgid, response, 1);
//      uint32_t m = millis();
//      String payload = _mysecDeviceState.mysecParser->makePayload(m, 2, false);
//      _mysecUdpNet.send(payload);
      MYSECSWITCH_DEBUGF2(F("retorno decode=%d\n"), r);
    } else {
      MYSECSWITCH_DEBUGLN(F("invalid token. Is Passkey synchronized?"));
    }
  }
}
void MysecWebsocketNet::send(const __FlashStringHelper *msgid, String& payload) {
  if (_mysecDeviceState.connType == MysecDeviceState::TYPE_WEBSOCKET && (_mysecDeviceState.state == MysecDeviceState::STATE_IDLE ||
    _mysecDeviceState.state == MysecDeviceState::STATE_HASDATA)) {
    String p;
    p.reserve(payload.length() + 55);
    p.concat(msgid); // F("SYNCH")
    p.concat(':');
    p.concat(MysecUtil::makeToken(payload.c_str(), _mysecDeviceState.passkey2));
    p.concat(':');
    p.concat(payload);
    MYSECSWITCH_DEBUGF2(F("Enviando: %s\n"), p.c_str());
    webSocket.sendTXT(p);
  }
}
void webSocketEvent(WStype_t type, uint8_t * payload, size_t lenght) {
  switch (type) {
  case WStype_DISCONNECTED: {
    MYSECSWITCH_DEBUGLN(F("Disconnected!\n"));
    _mysecDeviceState.state = MysecDeviceState::STATE_DISCONNECTED;
  }
  break;
  case WStype_ERROR: {
    MYSECSWITCH_DEBUGLN(F("Error!\n"));
  }
  break;
  case WStype_CONNECTED: {
    MYSECSWITCH_DEBUGF2(F("Connected to url: %s\n"), payload);
    _mysecDeviceState.state = MysecDeviceState::STATE_IDLE;
    _mysecDeviceState.connType = MysecDeviceState::TYPE_WEBSOCKET;
    }
  break;
  case WStype_TEXT: {
    MYSECSWITCH_DEBUGF2(F("get text: %s\n"), payload);
    _mysecWebsocketNet.resp.remove(0);
    _mysecWebsocketNet.resp.concat((const char *)payload);
  }
  break;
  case WStype_BIN:
    MYSECSWITCH_DEBUGF2(F("get binary lenght: %u\n"), lenght);
    //hexdump(payload, lenght, (uint8_t)16);

    // send data to server
    // webSocket.sendBIN(payload, lenght);
    break;
  }

}

MysecWebsocketNet _mysecWebsocketNet;
