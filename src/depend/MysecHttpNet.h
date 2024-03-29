/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * MysecHttpNet.h
 *
 *  Created on: 23 de dez de 2016
 *      Author: user2
 */

#ifndef MYSECHTTPNET_H_
#define MYSECHTTPNET_H_

#include <Arduino.h>
#include <ESP8266HTTPClient.h>

class MysecHttpNet {
protected:

public:
  MysecHttpNet();
  ~MysecHttpNet();
  bool getTime(HTTPClient &wc_http, bool force);
  /* Inclui a assinatura e envia a requisição. No retorno valida a assinatura
   * response é parâmetro de saída
   */
  int request(String& uri, String &payload, String &response, HTTPClient &wc_http);
};
extern MysecHttpNet _mysecHttpNet;
#endif /* MYSECHTTPNET_H_ */
