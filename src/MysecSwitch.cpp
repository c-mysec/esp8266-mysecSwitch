/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * MysecSwitch.cpp
 *
 *  Created on: 23 de dez de 2016
 *      Author: user2
 */

#include <Arduino.h>
#include <ArduinoJson.h>
#include "depend/BU64.h"
#include "MysecSwitch.h"
#include "depend/MysecUtil.h"
#include "depend/MysecDeviceState.h"
#include "depend/MysecUdpNet.h"
#include <Curve25519.h>
#include "depend/sha256.h"
#include "depend/MysecParser.h"
#include "depend/MysecWebsocketNet.h"
#include "depend/MysecHttpNet.h"
#include <Crypto.h>
#include "AES.h"
#include "CBC.h"

#ifndef MYSECSWITCH_NOFILE
#include "FS.h"
#endif

void MysecSwitch::init(const char * centralServerURL, uint64_t id, int port, const char * passk2) {
  uint8_t pk2[32];
  if (strlen(passk2) == 44) {
    BU64::decode(pk2, passk2, 44);
    init(centralServerURL, id, port, pk2);
  } else {
    // se não for passado passkey2 não funciona nada
    MYSECSWITCH_ERRORLN(F("Switch init passkey2 é obrigatório"));
  }
}
void MysecSwitch::init(const char * centralServerURL, uint64_t id, int port, const uint8_t * passk2) {
  MYSECSWITCH_INFOF(F("Switch init DEF_NUMPINS=%d\n"), DEF_NUMPINS);
  _mysecDeviceState.url = centralServerURL;
  _mysecDeviceState.id = id;
  _mysecDeviceState.numPins = 0;
  _mysecDeviceState.pb2.reserve(44);
  _mysecDeviceState.pb2.remove(0);
  for (uint8_t i = 0; i < DEF_NUMPINS; i++) {
    _mysecDeviceState.physicalPin[i] = 0;
    _mysecDeviceState.pinNextValue[i] = 0;
    _mysecDeviceState.pinNumber[i] = 0;
    _mysecDeviceState.pinValue[i] = 0;
    _mysecDeviceState.when[i] = 0;
    _mysecDeviceState.tempoLigado[i] = 0;
    _mysecDeviceState.tempoDesligado[i] = 0;
    _mysecDeviceState.setNextValueSet(i, false);
  }
  memcpy(_mysecDeviceState.passkey2, passk2, 32);
#ifndef MYSECSWITCH_NOFILE
  MYSECSWITCH_INFOLN(F("Switch init Gerenciamento de chaves em arquivo"));
  SPIFFS.begin();
  if (SPIFFS.exists(F("/mysec/c.c"))) {
    File f = SPIFFS.open(F("/mysec/c.c"), "r");
    uint8_t current[32];
    uint8_t old[32];
    String c = f.readStringUntil('\n');
    String o = f.readStringUntil('\n');
    if (o.length() >= 44 && c.length() >= 44) {
      int declen = BU64::decode(old, o.c_str(), 44);
      MYSECSWITCH_INFOLN(F("Switch init chave corrente recuperada"));
      if (declen == 32) {
        // se a chave antiga gravada é a mesma que está no código, então usa a chave nova gravada
        // a comparação com a chave antiga gravada é para previnir a regeração de chave manual.
        if (memcmp(old, _mysecDeviceState.passkey2, 32) == 0) {
          declen = BU64::decode(current, c.c_str(), 44);
          if (declen == 32) {
            memcpy(_mysecDeviceState.passkey2, current, 32);
            MYSECSWITCH_INFOLN(F("Switch init Usando chave corrente"));
            String p1 = f.readStringUntil('\n');
            if (p1.length() >= 44) {
              declen = BU64::decode(current, p1.c_str(), 44);
              if (declen == 32) {
                memcpy(_mysecDeviceState.passkey1, current, 32);
                MYSECSWITCH_INFOLN(F("Switch init Chave de usuário obtida"));
                if (port != 0) {
                  mysecUdpNet->init(port);
                }
              } else {
                MYSECSWITCH_ERRORLN(F("Switch init Chave de usuário inválida"));
                memset(_mysecDeviceState.passkey1, 0, 32);
              }
            } else {
              MYSECSWITCH_INFOLN(F("Switch init Chave de usuário não configurada"));
              memset(_mysecDeviceState.passkey1, 0, 32);
            }
            SPIFFS.end();
            return;
          }
        } else {
          MYSECSWITCH_INFOLN(F("Substituição de passkey2 do dispositivo"));
        }
      }
    }
    MYSECSWITCH_INFOLN(F("Switch init Usando chave original. Chave de usuário não configurada"));
    memset(_mysecDeviceState.passkey1, 0, 32);
    // o arquivo em disco está errado
    f.close();
    SPIFFS.remove(F("/mysec/c.c"));
  } else {
    MYSECSWITCH_INFOLN(F("Switch init Repositorio inexistente. Usando chave original. Chave de usuário não configurada"));
    memset(_mysecDeviceState.passkey1, 0, 32);
  }
  SPIFFS.end();
#endif
#ifdef MYSECSWITCH_NOFILE
  MYSECSWITCH_INFOLN(F("Switch init Gerenciamento externo de chaves"));
#endif
};
uint64_t MysecSwitch::getLastSynchTime() {
  return _mysecDeviceState.timeoffset;
}
uint64_t MysecSwitch::getLastSynchTimeOk() {
  return _mysecDeviceState.timeoffsetSyncOk;
}
int MysecSwitch::getLastHttpError() {
  return _mysecDeviceState.lastHttpError;
}
bool MysecSwitch::setupPin(uint8_t pinNumber, bool output, bool digital, bool automatic, uint8_t physicalPin) {
  return _mysecDeviceState.setupPin(pinNumber, output, digital, automatic, physicalPin);
}
bool MysecSwitch::setValue(uint8_t pinNumber, float pinValue) {
  return _mysecDeviceState.setValue(pinNumber, pinValue);
}
uint16_t MysecSwitch::getValue(uint8_t pinNumber) {
  return _mysecDeviceState.getValue(pinNumber);
}
bool MysecSwitch::resetValue(uint8_t pinNumber, float pinValue) {
  return _mysecDeviceState.resetValue(pinNumber, pinValue);
}
void MysecSwitch::persisteChaves() {
  SPIFFS.begin();
  String chaveOriginal; chaveOriginal.reserve(44);
  if (SPIFFS.exists(F("/mysec/c.c"))) {
    File f = SPIFFS.open(F("/mysec/c.c"), "r");
    // se a chave original está no arquivo, conserva ela
    String aChaveEmUso = f.readStringUntil('\n');
    String aChaveOriginal = f.readStringUntil('\n');
    if (aChaveOriginal.length() >= 44 && aChaveEmUso.length() >= 44) {
      chaveOriginal = aChaveOriginal;
    } else {
      MYSECSWITCH_ERRORLN(F("Switch persisteChaves arquivo de chaves corrompido"));
      // se a chave original não está no arquivo, então a chave atual em uso é a original
      BU64::encode(chaveOriginal, _mysecDeviceState.passkey2, 32);
    }
    f.close();
  } else {
    // se a chave original não está no arquivo, então a chave atual em uso é a original
    BU64::encode(chaveOriginal, _mysecDeviceState.passkey2, 32);
    MYSECSWITCH_INFOLN(F("Switch persisteChaves Chaves de disponitivo atual e original são a mesma."));
  }
  String passkey;passkey.reserve(44);
  BU64::encode(passkey, _mysecDeviceState.passkey2, 32);
  File f2 = SPIFFS.open(F("/mysec/c.c"), "w");
  f2.print(passkey);
  f2.print('\n');
  f2.print(chaveOriginal);
  f2.print('\n');
  passkey.remove(0);
  if (_mysecDeviceState.passkey1[0] != 0 && _mysecDeviceState.passkey1[1] != 0 && _mysecDeviceState.passkey1[2] != 0) {
    BU64::encode(passkey, _mysecDeviceState.passkey1, 32);
    MYSECSWITCH_INFOLN(F("Switch persisteChaves Chaves de dispositivo e usuário persistidas."));
  } else {
    MYSECSWITCH_INFOLN(F("Switch persisteChaves Chaves de dispositivo persistidas (não tem chave de usuário)."));
  }
  f2.print(passkey);
  f2.print('\n');
  f2.close();
  _mysecDeviceState.pb2.remove(0);
  SPIFFS.end();
}
bool MysecSwitch::processaChaveNova() {
  // se temos chave nova então processamos
  if (_mysecDeviceState.pb2.length() == 44) {
    uint8_t ipb2[32];
    if (BU64::decode(ipb2, _mysecDeviceState.pb2.c_str(), 44) == 32) {
      uint8_t sharedkey[32];
      _mysecDeviceState.pb2.remove(0);
      BU64::encode(_mysecDeviceState.pb2, _mysecDeviceState.nextPb1, 32);
      MYSECSWITCH_INFOLN(F("Switch processaChaveNova"));
      _mysecDeviceState.pb2.remove(0);
      BU64::encode(_mysecDeviceState.pb2, _mysecDeviceState.nextPk1, 32);
      delay(0);
      Curve25519::dh2(ipb2, _mysecDeviceState.nextPk1);
      memcpy(sharedkey, ipb2, 32);
      delay(0);
      uint8_t* hash;
      Sha256.init();
      Sha256.write(sharedkey, 32);
      hash = Sha256.result(); // 32 bytes
      // passa a usar a nova chave
      memcpy(_mysecDeviceState.passkey2, hash, 32);
      memset(_mysecDeviceState.nextPb1, 0, 32);
      memset(_mysecDeviceState.nextPk1, 0, 32);
      persisteChaves();
    }
    _mysecDeviceState.pb2.remove(0);
    // sinaliza para enviar mensagem para que o servidor também passe a usar a chave nova
    // caso contrário as mensagens do servidor seriam ignoradas até que o dispositivo enviasse uma mensagem
    _mysecDeviceState.lastSynch = 1;
    _mysecDeviceState.lastSynchOk = 1;
    return true;
  } else if (_mysecDeviceState.nextPk1[0] == 0
      && _mysecDeviceState.nextPk1[1] == 0 && _mysecDeviceState.nextPk1[2] == 0
      && _mysecDeviceState.nextPb1[0] == 0 && _mysecDeviceState.nextPb1[1] == 0
      && _mysecDeviceState.nextPb1[2] == 0) {
    // se a chave foi trocada então calculamos uma nova
    Curve25519::dh1(_mysecDeviceState.nextPb1, _mysecDeviceState.nextPk1);
    MYSECSWITCH_INFOLN(F("Switch processaChaveNova Novas chaves criadas"));
    return true;
  }
  return false;
}

void MysecSwitch::processaUdp() {
  // Agora processa UDP.
  if (mysecUdpNet->isConfigured() && !mysecUdpNet->makeSharedKey(_mysecDeviceState.passkey1)) {
    // se usamos udpNet e se não estamos fazendo sharedkey nova, sincronizamos UDP
    String resp = mysecUdpNet->receive(_mysecDeviceState.passkey1, _mysecDeviceState.id);
    if (resp.length() > 0) {
      MYSECSWITCH_DEBUGF(F("Switch processaUdp Recebida mensagem: %s\n"), resp.c_str());
      String msgid(F("USYNC"));
      if (_mysecDeviceState.mysecParser->decodeResponse(msgid, resp, 0, mysecUdpNet->isDesabilitaAutomatico())) {
        // a resposta é enviada no loop -> decodeResponse setou HAS_DATA
        String p = _mysecDeviceState.mysecParser->makePayload(millis(), 2, false);
        MYSECSWITCH_DEBUGF(F("Switch processaUdp Mensagem decodificada, enviando resposta %s\n"),
            p.c_str());
        mysecUdpNet->send(p);
      }
    } else {
    }
  }
}

void MysecSwitch::loop() {
  // atualiza os pinos programados
  for (int index = 0; index < _mysecDeviceState.numPins; index++) {
    // hab == 0 ==> respeita programacao. hab == -1 ==> desbilitado. hab < -1 ==> fired. hab > 0 temp desab
    if (
        _mysecDeviceState.getOutput(index) && ((_mysecDeviceState.getNextValueSet(index) && ((long)(millis() - _mysecDeviceState.when[index]) >= 0)))) {
      // se temos uma programação expirada, atualizamos o valor
      _mysecDeviceState.applyNext(index, mysecUdpNet->isDesabilitaAutomatico());
    }
  }
  // se temos chave nova então processamos
  if (!processaChaveNova()) {
    _mysecDeviceState.pb2.remove(0);
    // se não temos chave nova então podemos processar as mensagens
    // Http ou Websockets
    // primeiro vê a web
    if (_mysecDeviceState.numHttpErrors > 5) {
      _mysecDeviceState.lastSynch += 300000; // para por 5 minutos caso de muitos erros seguidos
      _mysecDeviceState.numHttpErrors = 0;
    }
    if (_mysecDeviceState.state == MysecDeviceState::STATE_DISCONNECTED) {
      conectaServidorCentral();
    } else if (((long)(millis() - (_mysecDeviceState.lastSynch + 30000))) >= 0 || _mysecDeviceState.lastSynch == 0) {
      MYSECSWITCH_DEBUGF(F("Switch loop Verificando sincronização a cada 30 segundos millis=%lu, lastSynch=%lu, lastSynchOk=%lu, connType=%d\n"), millis(),
          _mysecDeviceState.lastSynch, _mysecDeviceState.lastSynchOk, _mysecDeviceState.connType);
      // a cada 30 segundos
      // atualiza valores de leitura automática
      _mysecDeviceState.updateValues();
      _mysecDeviceState.lastSynch = millis();
      if (// a cada 5 minutos manda uma mensagem de qualquer forma, o servidor vai filtrar para 1 valor de leitura a cada 30 minutos
          (_mysecDeviceState.lastSynchOk <= 1 ||
              ((long)(millis() - _mysecDeviceState.lastSynchOk) >= 0) ||
              _mysecDeviceState.state == MysecDeviceState::STATE_HASDATA) &&
              _mysecDeviceState.connType == MysecDeviceState::TYPE_WEBSOCKET) {
          // agora pode processar normalmente
          // sincroniza
          {
            uint32_t m = millis();
            // msgid, token, device
            String payload = _mysecDeviceState.mysecParser->makePayload(m, 2, _mysecDeviceState.nextPb1[0] != 0 && _mysecDeviceState.nextPb1[1] != 0 && _mysecDeviceState.nextPb1[2] != 0);
            MYSECSWITCH_DEBUGLN(F("Switch loop Sincronizando com servidor e viewer"));
            mysecUdpNet->send(payload);
            _mysecWebsocketNet.send(F("SYNCH"), payload);
            // recebe resposta no callback
          }
          _mysecDeviceState.state = MysecDeviceState::STATE_IDLE;
      } else if (( // no caso de HTTP envia a cada 30 minutos
          // o servidor só vai aceitar 1 valor a cada 30 minutos
          (_mysecDeviceState.lastSynchOk <= 1 ||
              ((long)(millis() - _mysecDeviceState.lastSynchOk) >= 0) ||
              _mysecDeviceState.state == MysecDeviceState::STATE_HASDATA) &&
              _mysecDeviceState.connType == MysecDeviceState::TYPE_HTTP)) {
        // http
        HTTPClient wc_http;
        wc_http.setTimeout(10000);// milissegundos
        if (_mysecHttpNet.getTime(wc_http)) {
          uint32_t m = millis();
          String payload = _mysecDeviceState.mysecParser->makePayload(m, 2, _mysecDeviceState.nextPb1[0] != 0 && _mysecDeviceState.nextPb1[1] != 0 && _mysecDeviceState.nextPb1[2] != 0);
          MYSECSWITCH_DEBUGLN(F("Switch loop Sincronizando com servidor e viewer"));
          mysecUdpNet->send(payload);
          String response;
          String uri(F("/rest/device/synch"));
          bool resultado = _mysecHttpNet.request(uri, payload, response, wc_http) == 0;
          if (resultado) {
            String msgid(F("RSYNC"));
            _mysecDeviceState.state = MysecDeviceState::STATE_IDLE;
            _mysecDeviceState.mysecParser->decodeResponse(msgid, response, m, mysecUdpNet->isDesabilitaAutomatico());
          }
        }
      }
    }
    // Agora processa UDP.
    processaUdp();
  }
  if (_mysecDeviceState.state > MysecDeviceState::STATE_DISCONNECTED && _mysecDeviceState.connType == MysecDeviceState::TYPE_WEBSOCKET) {
    _mysecWebsocketNet.loop(mysecUdpNet->isDesabilitaAutomatico());
  }
}
CBC<AES256> cipher;

void MysecSwitch::conectaServidorCentral() {
  _mysecDeviceState.flags &= 0xFE;
  for (int i = 0; i < DEF_NUMPINS; i++) {
    if (_mysecDeviceState.getOutput(i)) {
      _mysecDeviceState.flags |= 1;
    }
  }
  if (_mysecDeviceState.url.length() == 0) return;
  // tenta obter primeira conexão somente após 30 segundos
  if (((long)(millis() - (_mysecDeviceState.lastSynch + 29990))) >= 0 || _mysecDeviceState.lastSynch == 0) {
    // obtém time
    HTTPClient wc_http;
    _mysecDeviceState.lastSynch = millis();
    // tenta conectar -- tudo de uma vez para não precisar guardar a URL
    wc_http.setTimeout(10000);// milissegundos
    if (_mysecHttpNet.getTime(wc_http)) {
      // obtém URL
      uint32_t m = millis();
      String payload = _mysecDeviceState.mysecParser->makeUrlRequest(m);
      String response;
      MYSECSWITCH_DEBUGF(F("Switch connectaServidorCentral UrlRequest enviando requisição %s\n"), payload.c_str());
      String uriUrlRequest(F("/rest/websocketurl/device"));
      bool resultado = _mysecHttpNet.request(uriUrlRequest, payload, response, wc_http) == 0;
      _mysecDeviceState.lastSynchOk = 0;
      if (resultado) {
        MYSECSWITCH_DEBUGF(F("Switch connectaServidorCentral Response: %s\n"), response.c_str());
        StaticJsonBuffer<1000> jsonBuffer;
        JsonObject& rdata = jsonBuffer.parseObject(response);
        if (!rdata.success()) {
          MYSECSWITCH_ERRORLN(F("Switch connectaServidorCentral UrlRequest parseObject() failed"));
          return; // continua no estado 0 e tenta novamente mais tarde
        }
        if (!_mysecDeviceState.mysecParser->decodeResponseNewKeyTime(rdata, m)) {
          MYSECSWITCH_ERRORLN(F("Switch connectaServidorCentral UrlRequest timestamp failed"));
          return; // continua no estado 0 e tenta novamente mais tarde
        }
        if (_mysecDeviceState.pb2.length() == 44) {
          MYSECSWITCH_INFOLN(F("Switch connectaServidorCentral UrlRequest Regerar chaves a pedido do servidor"));
          return;
        }
        String wshost = rdata[F("host")];
        String wsport = rdata[F("port")];
        String wssecure = rdata[F("connectionType")];
        String wsauth = rdata[F("token")];
        String wsuri; wsuri.reserve(200);
        String uri = rdata[F("uri")];
        String p1 = rdata[F("pp")];
        String ivs = rdata[F("bb")];
        if (p1 && p1.length() >= 44 && ivs && ivs.length() == 24) {
          BU64::decode(_mysecDeviceState.passkey1, p1.c_str(), 44);
          uint8_t iv[16];
          BU64::decode(iv, ivs.c_str(), 24);
          cipher.clear();
          cipher.setKey(_mysecDeviceState.passkey2, cipher.keySize());
          cipher.setIV(iv, cipher.ivSize());
          cipher.decrypt(_mysecDeviceState.passkey1, _mysecDeviceState.passkey1, 32);
//          response.remove(0);
//          BU64::encode(response, _mysecDeviceState.passkey1, 32);
//          MYSECSWITCH_DEBUGF(F("Switch connectaServidorCentral key: %s"), response.c_str());

          persisteChaves();
          MYSECSWITCH_INFOLN(F("Trocando chaves de usuário. Restart."));
          delay(1000);
          ESP.restart();
        }
        wsuri.concat(uri);
        wsuri.concat('?');
        wsuri.concat(F("device="));
        wsuri.concat(MysecUtil::ulltoa(_mysecDeviceState.id));
        wsuri.concat(F("&token1="));
        wsuri.concat(wsauth);
        wsuri.concat(F("&time="));
        int32_t elapsed = (millis() - _mysecDeviceState.lasttimeMillis);
        wsuri.concat(MysecUtil::ulltoa(_mysecDeviceState.timeoffset + elapsed));
        String payload; payload.reserve(60);
        payload.concat(MysecUtil::ulltoa(_mysecDeviceState.id));
        payload.concat(':');
        payload.concat(wsauth);
        payload.concat(':');
        payload.concat(MysecUtil::ulltoa(_mysecDeviceState.timeoffset + elapsed));
        wsuri.concat(F("&token2="));
        wsuri.concat(MysecUtil::makeToken(payload.c_str(), _mysecDeviceState.passkey2));
        if (wssecure.equals(F("wss")) && ((_mysecDeviceState.flags & 1) > 0)) {
          _mysecWebsocketNet.connect(true, wshost.c_str(), wsport.toInt(), wsuri.c_str());
          _mysecDeviceState.state = MysecDeviceState::STATE_CONNECTING;
          _mysecDeviceState.connType = MysecDeviceState::TYPE_WEBSOCKET;
        } else if (wssecure.equals(F("ws")) && ((_mysecDeviceState.flags & 1) > 0)) {
          _mysecWebsocketNet.connect(false, wshost.c_str(), wsport.toInt(), wsuri.c_str());
          _mysecDeviceState.state = MysecDeviceState::STATE_CONNECTING;
          _mysecDeviceState.connType = MysecDeviceState::TYPE_WEBSOCKET;
        } else {
          // ficamos com HTTP --> só vai mudar se der reset.
          MYSECSWITCH_INFOLN(F("Switch connectaServidorCentral Ficamos com HTTP\n"));
          _mysecDeviceState.state = MysecDeviceState::STATE_IDLE;
          _mysecDeviceState.connType = MysecDeviceState::TYPE_HTTP;
        }
      }
    }
  }
}
