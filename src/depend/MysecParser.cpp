/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * MySecParser.cpp
 *
 *  Created on: 23 de dez de 2016
 *      Author: user2
 */

#include <Arduino.h>
#include "MysecParser.h"
#include <ArduinoJson.h>
#include "sha256.h"
#include "BU64.h"
#include "MysecDeviceState.h"
#include "MysecUtil.h"

String MysecParser::makePayload(uint32_t m, int fase, bool sendNextPb1) {
  StaticJsonBuffer<1000> jsonBuffer;
  JsonObject& root = jsonBuffer.createObject();
  root[F("id")] = MysecUtil::ulltoa(_mysecDeviceState.id);
  int32_t elapsed = (millis() - _mysecDeviceState.lasttimeMillis);
  root[FPSTR(PM_TIME)] = MysecUtil::ulltoa(_mysecDeviceState.timeoffset + elapsed);
  if (fase > 0) {
    root[FPSTR(PM_FASE)] = fase;
  }
  root[FPSTR(PM_TAG1)] = _mysecDeviceState.tag1;
  root[FPSTR(PM_TAG2)] = _mysecDeviceState.tag2;
  JsonArray& pins = root.createNestedArray(JFS(PM_PINS));
  for (int i = 0; i < _mysecDeviceState.numPins; i++) {
    JsonObject& pin = pins.createNestedObject();
    pin[FPSTR(PM_PINNUMBER)] = _mysecDeviceState.pinNumber[i];
    pin[F("lastKnownValue")] = _mysecDeviceState.getValue(_mysecDeviceState.pinNumber[i]);
  }
  root[FPSTR(PM_S)] = m;
  if (sendNextPb1) {
    String c;
    c.reserve(45);
    BU64::encode(c, _mysecDeviceState.nextPb1, 32);
    root[FPSTR(PM_NEWKEY)] = c;
  }
  String buffer; buffer.reserve(root.measureLength() + 1);
  root.printTo(buffer);
  return buffer;
}
String MysecParser::makeUrlRequest(uint32_t m) {
  StaticJsonBuffer<1000> jsonBuffer;
  JsonObject& root = jsonBuffer.createObject();
  root[F("id")] = MysecUtil::ulltoa(_mysecDeviceState.id);
  int32_t elapsed = (m - _mysecDeviceState.lasttimeMillis);
  root[FPSTR(PM_TIME)] = MysecUtil::ulltoa(_mysecDeviceState.timeoffset + elapsed);
  root[FPSTR(PM_FASE)] = 0;
  root[FPSTR(PM_S)] = m;
  String buffer;
  buffer.reserve(root.measureLength()+1);
  root.printTo(buffer);
  return buffer;
}
bool MysecParser::decodeResponse(const String& msgid, const String &resp, uint32_t m) {
  StaticJsonBuffer<1000> jsonBuffer;
  JsonObject& root = jsonBuffer.parseObject(resp);
  if (!root.success())
  {
    MYSECSWITCH_DEBUGLN(F("parseObject() failed"));
    return false;
  }
  if (m > 0) {
    return decodeResponse2(root[F("data")], m);
  } else {
    MYSECSWITCH_DEBUGLN(F("Sem o wrapper DATA"));
    return decodeResponse2(root, m);
  }
}
bool MysecParser::decodeResponseNewKeyTime(JsonObject& rdata, uint32_t m) {
  if (rdata.containsKey(JFS(PM_NEWKEY))) {
    String rpb2 = rdata[FPSTR(PM_NEWKEY)];
    if (rpb2.length() >= 44) {
      _mysecDeviceState.pb2.remove(0);
      _mysecDeviceState.pb2.concat(rpb2);
      MYSECSWITCH_DEBUGF2(F("Recebendo nova chave pb2 %s\n"), _mysecDeviceState.pb2.c_str());
    }
  }
  if (m > 1 && rdata.containsKey(JFS(PM_TIME))) {
    String t = rdata[FPSTR(PM_TIME)];
    MYSECSWITCH_DEBUGF2(F("time=%s\n"), t.c_str());
    _mysecDeviceState.timeoffset = MysecUtil::atoull(t);
    _mysecDeviceState.lasttimeMillis = millis(); // guarda o offset de millis
  }
  if (!rdata.containsKey(JFS(PM_S))) {
    String s;
    rdata.prettyPrintTo(s);
    MYSECSWITCH_DEBUGF2(F("Não encontrou timestamp: %s\n"), s.c_str());
    return false;
  } else {
    uint32_t m2 = rdata[FPSTR(PM_S)];
    if (m > 1 && m2 != m) {
      MYSECSWITCH_DEBUGLN(F("timestamp incorreto"));
      return false;
    }
  }
  if (rdata.containsKey(JFS(PM_TAG1))) {
    // TAG Flag
    uint32_t t1 = rdata[FPSTR(PM_TAG1)];
    uint32_t t2 = rdata[FPSTR(PM_TAG2)];
    if ((t1 != 0 || t2 != 0) && (t1 > _mysecDeviceState.tag1 || (t1 == _mysecDeviceState.tag1 && t2 > _mysecDeviceState.tag2))) {
      _mysecDeviceState.flags |= 0x80;
    }
    MYSECSWITCH_DEBUGF2(F("tag1:%lu, tag2:%lu\n"), _mysecDeviceState.tag1, _mysecDeviceState.tag2);
  }
  return true;
}
bool MysecParser::decodeResponse2(JsonObject& rdata, uint32_t m) {
  if (!decodeResponseNewKeyTime(rdata, m)) {
    return false;
  }
  if (rdata.containsKey(JFS(PM_PINS)) && rdata[FPSTR(PM_PINS)].is<JsonArray&>()) {// && id == _mysecDeviceState.id) {
    JsonArray& remotepins = rdata[FPSTR(PM_PINS)].asArray();
    int remotepinslen = remotepins.size();
    long agora = millis();
    for (int i = 0; i < remotepinslen; i++) {
      JsonObject& rpin = remotepins[i];
      uint8_t num = ((uint8_t)rpin[FPSTR(PM_PINNUMBER)]);
      bool nextValueSet = rpin[F("nextValueSet")] == 1;
      if (nextValueSet) {
        MYSECSWITCH_DEBUGF2(F("Processando novo valor do pino=%d, estado=%d\n"), num, _mysecDeviceState.state);
        if (_mysecDeviceState.state >= MysecDeviceState::STATE_IDLE) {
          _mysecDeviceState.state = MysecDeviceState::STATE_HASDATA;
        }
        for (int j = 0; j < _mysecDeviceState.numPins; j++) {
          // só deixa intermitente se continuar recebendo a programação (isso é por que o usuário pode desabilitar ou excluir o programa enquanto estiver no intervalo)
          _mysecDeviceState.tempoLigado[j] = 0;
          _mysecDeviceState.tempoDesligado[j] = 0;
          MYSECSWITCH_DEBUGF2(F("verificando com pino=%d\n"), _mysecDeviceState.pinNumber[j]);
          if (_mysecDeviceState.pinNumber[j] == num) {
            if (rpin.containsKey(JFS(PM_TEMPOLIGADO)) && rpin.containsKey(JFS(PM_TEMPODESLIGADO)) &&
              rpin[FPSTR(PM_TEMPOLIGADO)] > 0 && rpin[FPSTR(PM_TEMPODESLIGADO)] > 0) {
              // intermitente
              if (rpin[F("nextValue")] == LOW) {
                MYSECSWITCH_DEBUGF2(F("Fim da programação em =%d\n"), (uint32_t)rpin[F("quando")]);
                // fim da programação
                // desliga quando expirar e não repete mais
                _mysecDeviceState.when[j] = rpin[F("quando")]; // quando vai mudar para o pinNextValue, valor ajustado para o millis() local.
                _mysecDeviceState.when[j] = _mysecDeviceState.when[j] * 1000; // a transmissão é em segundos e guardamos milissegundos
                _mysecDeviceState.pinNextValue[j] = LOW; // até 1024
                if (_mysecDeviceState.when[j] <= 10000) {
                  _mysecDeviceState.applyNext(j);
                } else {
                  _mysecDeviceState.when[j] += agora;
                }
              } else if (_mysecDeviceState.tempoLigado[j] <= 0) {
                MYSECSWITCH_DEBUGF2(F("Nova programação em =%d\n"), (uint32_t)rpin[F("quando")]);
                // nova programação
                _mysecDeviceState.pinNextValue[j] = HIGH;
                _mysecDeviceState.when[j] = rpin[F("quando")]; // quando vai mudar para o pinNextValue, valor ajustado para o millis() local.
                _mysecDeviceState.when[j] = _mysecDeviceState.when[j] * 1000; // a transmissão é em segundos e guardamos milissegundos
                MYSECSWITCH_DEBUGF2(F("Disparando programação em =%d\n"), _mysecDeviceState.when[j]);
                if (_mysecDeviceState.when[j] <= 10000) {
                  // se temos uma programação expirada, atualizamos o valor
                  _mysecDeviceState.applyNext(j);
                } else {
                  _mysecDeviceState.when[j] += agora;
                }
              } else {
                MYSECSWITCH_DEBUGLN(F("ajustando programação"));
                // caso contrário só ajusta o tempo ligado e desligado
              }
            } else {
              // nao eh intermitente - manual ou prog?
              _mysecDeviceState.pinNextValue[j] = rpin[F("nextValue")];
              _mysecDeviceState.setNextValueSet(j, rpin[F("nextValueSet")] == 1);
              _mysecDeviceState.when[j] = rpin[F("quando")]; // quando vai mudar para o pinNextValue, valor ajustado para o millis() local.
              _mysecDeviceState.when[j] = _mysecDeviceState.when[j] * 1000; // a transmissão é em segundos e guardamos milissegundos
  #ifdef MYSECSWITCH_DEBUG
    String p; p.reserve(50);
    p.concat(FPSTR("Novo valor recebido "));
    p.concat(_mysecDeviceState.pinNextValue[j]);
    p.concat(F(" no pino "));
    p.concat(_mysecDeviceState.pinNumber[j]);
    MYSECSWITCH_DEBUGF2(F("%s nextValueSet:%s\n"), p.c_str(), _mysecDeviceState.getNextValueSet(j) ? "true" : "false");
  #endif
    MYSECSWITCH_DEBUGF2(F("Free dynamic memory:%ld\n"), ESP.getFreeHeap());
              if (_mysecDeviceState.getNextValueSet(j)) {
                if (_mysecDeviceState.when[j] <= 10000) {
                  // se temos uma programação expirada, atualizamos o valor
                  _mysecDeviceState.applyNext(j);
                } else {
                  _mysecDeviceState.when[j] += agora;
                }
              }
            }
            _mysecDeviceState.tempoLigado[j] = rpin[F("tempoLigado")];
            _mysecDeviceState.tempoDesligado[j] = rpin[F("tempoDesligado")];
            break;
          }
        }
      }
    }
  } else {
    if (m > 0) {
      MYSECSWITCH_DEBUGLN(F("Não encontrou pins"));
      return false;
    }
  }
  return true;
}
