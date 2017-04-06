/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * UdpNet.cpp
 *
 *  Created on: 6 de set de 2016
 *      Author: user
 */

#include "sha256.h"
#include "BU64.h"
#include <ESP8266WiFi.h>
#include <Curve25519.h>
#include <ArduinoJson.h>
#include "depend/MysecDeviceState.h"
#include "MysecUtil.h"
#include "MysecUdpNet.h"

void MysecUdpNet::init(int port) {
  if (port > 0) {
    MYSECSWITCH_INFOF(F("UdpNet init Begin port:%d\n"), port);
    udpClient.begin(port);
  }
  memset(pb2, 0, 32);
}

MysecUdpNet::~MysecUdpNet() {
	udpClient.stop();
}
/**
 * passkey : chave do usuario. pubkey : chave public gerada a partir da chave do usuario
 */
String MysecUdpNet::receive(const uint8_t * passkey, uint64_t deviceId) {
	int cb = udpClient.parsePacket();
	if (cb) {
	  MYSECSWITCH_DEBUGF(F("UdpNet receive cb:%d\n"), cb);
    uint8_t * buffer = new uint8_t[cb];
    udpClient.readBytes(buffer, cb);
#if MYSECSWITCH_DEBUG>2
    String tPrint; tPrint.reserve(44);
#endif
    uint16_t siz = readInt(buffer);
    if (siz != 0) {
      String s;
      s.reserve(cb);
      for (int i = 0; i < cb && buffer[i] != 0; i++) {
          s += (char) buffer[i];
      }
      delete[] buffer;
	    int pos = s.indexOf(';');
	    String payload = s.substring(pos + 1);
	    MYSECSWITCH_INFOF(F("UdpNet receive Recebido: %s\n"), s.c_str());
	    int fase, des2;
	    {
	      StaticJsonBuffer<1000> jsonBuffer;
	      JsonObject& data = jsonBuffer.parseObject(payload);
	      if (!data.success()) {
	        MYSECSWITCH_ERRORF(F("UdpNet receive parseObject() failed %s\n"), payload.c_str());
	        return "";
	      }
	      fase = data[FPSTR(PM_FASE)];
	      String des1 = data[FPSTR(PM_DESAFIO1)];
	      des2 = data[FPSTR(PM_DESAFIO2)];
	      if (fase == 1) {
	        BU64::decode(pb2, des1.c_str(), 44);
	      }
	    }
	    if (fase == 1) {
	      memset(sessionKey, 0, 32);
	      // valida a mensagem inicial com HMAC da chave do usuario
	      if (!MysecUtil::validateToken(payload.c_str(), s.c_str(), passkey)) {
	        MYSECSWITCH_ERRORF(F("UdpNet receive Falhou o hash da mensagem payload:%s token:%s gentoken:%s\n"), payload.c_str(), s.c_str(), MysecUtil::makeToken(payload.c_str(), passkey).c_str());
	        memset(pb2, 0 ,32);
	        return "";
	      }
	      yield();
	      StaticJsonBuffer<1000> jsonBuffer;
	      JsonObject& root = jsonBuffer.createObject();
	      // retorna o ok
	      root[FPSTR(PM_FASE)] = 1;
	      root[FPSTR(PM_DESAFIO1)] = des2;
	      root[FPSTR(PM_DESAFIO3)] = random(10,10000);
	      root[FPSTR(PM_DESAFIO4)] = MysecUtil::ulltoa(deviceId);
	      root["s"] = millis();
	      String sendPayload;
	      sendPayload.reserve(root.measureLength()+1);
	      root.printTo(sendPayload);
	      // fase 1 ainda envia com assinatura com a chave do usuário
//	      Sha256.initHmac(passkey, 32); // key, and length of key in bytes
//	      Sha256.print(sendPayload);
//	      hash = Sha256.resultHmac(); // 32 bytes
//	      String sendHash; sendHash.reserve(44);
//	      BU64::encode(sendHash, hash, 32);
	      String sendHash = MysecUtil::makeToken(sendPayload.c_str(), passkey);
	      MYSECSWITCH_DEBUGF(F("UdpNet receive enviando resposta para %s:%d payload %s SendHash:%s\n"), udpClient.remoteIP().toString().c_str(), udpClient.localPort(), sendPayload.c_str(), sendHash.c_str());
	      remote = udpClient.remoteIP();
	      udpClient.beginPacket(udpClient.remoteIP(), udpClient.localPort());
	      udpClient.print(sendHash);
	      udpClient.print(";");
	      udpClient.print(sendPayload);
	      udpClient.endPacket();
	    } else if (fase == 2 && (sessionKey[0] != 0 || sessionKey[1] != 0 || sessionKey[2] != 0)) {
	      // pedido de estado
        yield();
        if (!MysecUtil::validateToken(payload.c_str(), s.c_str(), sessionKey)) {
	        MYSECSWITCH_ERRORLN(F("UdpNet receive Assinatura fase 2 invalida"));
	        return "";
	      }
	      return payload;
      } else {
        MYSECSWITCH_ERRORLN(F("UdpNet receive mensagem em fase nao reconhecida"));
	    }
		}
	}
	return "";
}
bool MysecUdpNet::makeSharedKey(const uint8_t * passkey) {
	if (pb2[0] != 0 || pb2[1] != 0 || pb2[2] != 0) {
#if MYSECSWITCH_DEBUG>2
    String b; b.reserve(45);
    BU64::encode(b, pb2, 32);
    MYSECSWITCH_DEBUGF(F("UdpNet makeSharedKey pb2 : %s\n"), b.c_str());
#endif
		// gera shared
    uint8_t f[32];
		memcpy(f, passkey, 32);
		f[0] &= 248;
		f[31] &= 127;
		f[31] |= 64;
		memcpy(sessionKey, pb2, 32);
		// já responde usando a sessionkey
		Curve25519::dh2(sessionKey, f);
		//curve25519_donna(sessionKey, pk1, pb2);
#if MYSECSWITCH_DEBUG>2
		b.remove(0);
		BU64::encode(b, sessionKey, 32);
		MYSECSWITCH_DEBUGF(F("UdpNet makeSharedKey sessionKey : %s\n"), b.c_str());
#endif
		memset(pb2, 0 ,32);
		return true;
	} else {
		return false;
	}
}
void MysecUdpNet::send(String& payload) {
  if (sessionKey[0] != 0 || sessionKey[1] != 0 || sessionKey[2] != 0) {
    MYSECSWITCH_INFOF(F("UdpNet send enviando resposta para %s : %s\n"), remote.toString().c_str(), payload.c_str());
    udpClient.beginPacket(remote, udpClient.localPort());
    udpClient.print(MysecUtil::makeToken(payload.c_str(), sessionKey));
    udpClient.write(';');
    udpClient.print(payload);
    udpClient.endPacket();
  }
}
uint16_t MysecUdpNet::readInt(uint8_t * buffer) {
  return buffer[1] * 256 + buffer[0]; // big enddian
}
uint32_t MysecUdpNet::readLong(uint8_t * buffer) {
  return buffer[3] * 16777216 + buffer[2] * 65536 + buffer[1] * 256 + buffer[0]; // big enddian
}
bool MysecUdpNet::isConfigured() {
  // temos UDP se estado for != 0
  return estado != 0;
}
bool MysecUdpNet::isDesabilitaAutomatico() {
  return estado != 0 && (hab == -1 || // se desabilitado/alarme desativado (-1) ou
      // udpNet->hab != 0 --> menor que -1 é fired, maior que 0 é imhome -- em ambos os casos desabilita por um período
      ((hab != 0) && millis() < nextEventHab));
}
bool MysecUdpNet::isEventExpired() {
  return millis() >= nextEventHab;
}
uint32_t MysecUdpNet::getNextEventHab() {
  return nextEventHab;
}
void MysecUdpNet::setNextEventHab(uint32_t next) {
  nextEventHab = next;
}
