/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * MySecWebsocketNet.cpp
 *
 *  Created on: 23 de dez de 2016
 *      Author: user2
 */

#include <depend/MysecDeviceState.h>
#include <depend/MysecParser.h>
#include <depend/MysecUtil.h>
#include <depend/MysecWebsocketNet.h>
#include <stddef.h>
#include <WebSockets.h>
#include <WebSocketsClient.h>
#include <WString.h>
#include <cstdint>

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
    MYSECSWITCH_INFOF(F("WebsocketNet connect Iniciando websocket: wss://%s:%d%s\n"), wshost, wsport, wsuri);
    webSocket.beginSSL(wshost, wsport, wsuri);
  } else {
    MYSECSWITCH_INFOF(F("WebsocketNet connect Iniciando websocket: ws://%s:%d%s\n"), wshost, wsport, wsuri);
    webSocket.begin(wshost, wsport, wsuri);
  }
  webSocket.onEvent(webSocketEvent);
  return true;
}
void MysecWebsocketNet::loop(bool isDesabilitaAutomatico) {
  if (_mysecDeviceState.state <= MysecDeviceState::STATE_CONNECTING) {
    webSocket.loop();
  } else if (!webSocket.loop1()) {
    _mysecDeviceState.state = MysecDeviceState::STATE_DISCONNECTED;
  }
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
    if (respToken == respToken2) {
      MYSECSWITCH_DEBUGF(F("WebsocketNet loop Response=%s\n"), response.c_str());
      bool r = _mysecDeviceState.mysecParser->decodeResponse(msgid, response, 1, isDesabilitaAutomatico);
      MYSECSWITCH_DEBUGF(F("WebsocketNet loop retorno decode=%d\n"), r);
      _mysecDeviceState.lastSynch = 1;
    } else {
      MYSECSWITCH_DEBUGF(F("WebsocketNet loop Response=%s, respToken=%s, gen respToke=%s\n"), response.c_str(), respToken.c_str(), respToken2.c_str());
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
    MYSECSWITCH_INFOF(F("WebsocketNet send Enviando: %s\n"), p.c_str());
    if (webSocket.sendTXT(p)) {
      _mysecDeviceState.setNextSynch();
    }
  }
}
void MysecWebsocketNet::disconnect() {
  if (_mysecDeviceState.state != MysecDeviceState::STATE_DISCONNECTED) {
    webSocket.disconnect();
  }
}
void webSocketEvent(WStype_t type, uint8_t * payload, size_t lenght) {
  switch (type) {
  case WStype_DISCONNECTED: {
    _mysecDeviceState.state = MysecDeviceState::STATE_DISCONNECTED;
    webSocket.disconnect();
    MYSECSWITCH_ERRORLN(F("WebsocketNet webSocketEvent Disconnected!\n"));
  }
  break;
  case WStype_ERROR: {
    MYSECSWITCH_ERRORLN(F("WebsocketNet webSocketEvent Error!\n"));
  }
  break;
  case WStype_CONNECTED: {
    MYSECSWITCH_DEBUGF(F("WebsocketNet webSocketEvent Connected to url: %s\n"), payload);
    _mysecDeviceState.state = MysecDeviceState::STATE_IDLE;
    _mysecDeviceState.connType = MysecDeviceState::TYPE_WEBSOCKET;
    }
  break;
  case WStype_TEXT: {
    MYSECSWITCH_INFOF(F("WebsocketNet webSocketEvent get text: %s\n"), payload);
    _mysecWebsocketNet.resp.remove(0);
    _mysecWebsocketNet.resp.concat((const char *)payload);
  }
  break;
  case WStype_BIN:
    MYSECSWITCH_DEBUGF(F("WebsocketNet webSocketEvent get binary lenght: %u\n"), lenght);
    //hexdump(payload, lenght, (uint8_t)16);

    // send data to server
    // webSocket.sendBIN(payload, lenght);
    break;
  }

}

MysecWebsocketNet _mysecWebsocketNet;
