/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */


/*
 * MySecWebsocketNet.h
 *
 *  Created on: 23 de dez de 2016
 *      Author: user2
 */

#ifndef MYSECWEBSOCKETNET_H_
#define MYSECWEBSOCKETNET_H_

#include <Arduino.h>
// também recebe mensagens pelo websocket, valida a assinatura e repassa para o parser
class MysecWebsocketNet {
public:
  String resp;
  MysecWebsocketNet();
  ~MysecWebsocketNet();
  // conecta de forma segura no websocket
  // se retornar true então muda de estado
  //_mysecDeviceState.state = MysecDeviceState::STATE_CONNECTING;
  bool connect(bool wssecure, const char* wshost, int wsport, const char* wsuri);
  void disconnect();
  // envia a mensagem acrescentando a assinatura
  void send(const __FlashStringHelper *msgid, String& payload);
  void loop(bool isDesabilitaAutomatico);
};
extern MysecWebsocketNet _mysecWebsocketNet;
#endif /* MYSECWEBSOCKETNET_H_ */
