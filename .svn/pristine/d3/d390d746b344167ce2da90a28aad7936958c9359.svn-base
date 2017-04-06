/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * UdpNet.h
 *
 *  Created on: 6 de set de 2016
 *      Author: user
 */

#ifndef LIBRARIES_MYSEC_UDPNET_H_
#define LIBRARIES_MYSEC_UDPNET_H_
#include <Arduino.h>
#include <WiFiUdp.h>

class MysecUdpNet {
public:
  enum MESSAGE_TYPES : int16_t { MSG_DUMMY, MSG_PINCHANGE, MSG_IMHOME, MSG_ALARMDISABLED, MSG_ALARMNOTURNO, MSG_SWITCHSTATE, MSG_ALARMFIRED, MSG_SWITCHTESTFIRED, MSG_ALARMSTATUS, MSG_ALARMENABLED};
	WiFiUDP udpClient;
	IPAddress remote;
	uint32_t readLong(uint8_t * buffer);
  uint8_t sessionKey[32];
  uint8_t pb2[32];
  long hab = 0; // hab == 0 ==> respeita programacao. hab == -1 ==> desbilitado. hab < -1 ==> fired. hab > 0 temp desab
  // desabilitado significa que nao recebe prog do servidor mas obedec local e manual do servidor.
  // TODO: colocar flag de manual/prog na resposta do servidor.
  uint32_t nextEventHab = 0;
  uint16_t readInt(uint8_t * buffer);
  uint8_t estado = 0;
	MysecUdpNet() {};
	virtual ~MysecUdpNet();
	void init(int port);
	virtual String receive(const uint8_t * passkey, uint64_t deviceId);
	bool makeSharedKey(const uint8_t * passkey);
  void send(String& payload);
	bool isConfigured();
	bool isDesabilitaAutomatico();
	/* true se o próximo evento chegou ou passou */
	bool isEventExpired();
  void setNextEventHab(uint32_t next);
  uint32_t getNextEventHab();

  long getHab() const {
    return hab;
  }

  void setHab(long hab = 0) {
    this->hab = hab;
  }
};
#endif /* LIBRARIES_MYSEC_UDPNET_H_ */
