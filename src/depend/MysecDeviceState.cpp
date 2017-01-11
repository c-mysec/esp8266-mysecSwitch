/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * MysecDeviceState.cpp
 *
 *  Created on: 23 de dez de 2016
 *      Author: user2
 */

#include <Arduino.h>
#include "MysecDeviceState.h"
#include "MysecUtil.h"
#include <Curve25519.h>

#include "MysecUdpNet.h"

void MysecDeviceState::setNextValueSet(uint8_t pin, bool f) {
  pinFlags[pin] ^= (-f ^ pinFlags[pin]) & 1;
}
bool MysecDeviceState::getNextValueSet(uint8_t pin) {
  return pinFlags[pin] & 1;
}
void MysecDeviceState::setOutput(uint8_t pin, bool f) {
  pinFlags[pin] ^= (-f ^ pinFlags[pin]) & (1 << 1);
}
bool MysecDeviceState::getOutput(uint8_t pin) {
  return (pinFlags[pin] >> 1) & 1;
}
void MysecDeviceState::setDigital(uint8_t pin, bool f) {
  pinFlags[pin] ^= (-f ^ pinFlags[pin]) & (1 << 2);
}
bool MysecDeviceState::getDigital(uint8_t pin) {
  return (pinFlags[pin] >> 2) & 1;
}
void MysecDeviceState::setAutomatic(uint8_t pin, bool f) {
  pinFlags[pin] ^= (-f ^ pinFlags[pin]) & (1 << 3);
}
bool MysecDeviceState::getAutomatic(uint8_t pin) {
  return (pinFlags[pin] >> 3) & 1;
}
bool MysecDeviceState::setupPin(uint8_t pin, bool poutput, bool pdigital, bool pautomatic, uint8_t pphysicalPin) {
  if (numPins < DEF_NUMPINS) {
    for (int i = 0; i < numPins; i++) {
      if (pinNumber[i] == pin) {
        return false;
      }
    }
    pinNumber[numPins] = pin;
    setOutput(numPins, poutput);
    setDigital(numPins, pdigital);
    setAutomatic(numPins, pautomatic);
    pinNextValue[numPins] = 0;
    setNextValueSet(numPins, false);
    physicalPin[numPins] = pphysicalPin;
    if (pautomatic) {
      if (poutput) {
        pinMode(pphysicalPin, OUTPUT);
      } else {
        pinMode(pphysicalPin, INPUT);
      }
    }
    numPins++;
    return true;
  }
  return false;
}
void MysecDeviceState::updateValues() {
  for (int index = 0; index < numPins; index++) {
    if (!getOutput(index) && getAutomatic(index)) {
      // guarda o valor antigo
      uint16_t value = pinValue[index];
      // lê o valor novo
      if (getDigital(index)) {
        pinValue[index] = digitalRead(physicalPin[index]);
      } else {
        // somente ESP8266
        if (pinNumber[index] == A0) {
          pinValue[index] = analogRead(physicalPin[index]);
        } else {
          pinValue[index] = digitalRead(physicalPin[index]);
        }
      }
      // se o novo valor for diferente do anterior marca para enviar.
      if (value != pinValue[index]) {
        if (state == STATE_IDLE) state = STATE_HASDATA;
      }
    }
  }
}
uint16_t MysecDeviceState::getValue(uint8_t pin) {
  uint8_t index = 10;
  for (int i = 0; i < numPins; i++) {
    if (pinNumber[i] == pin) {
      index = i;
      break;
    }
  }
  if (index < numPins) {
    if (!getOutput(index)) {
      // se o pino for de input, o valor foi lido via digitalRead ou analogRead ou foi inserido via setValue()
      if (getAutomatic(index)) {
        uint16_t value = pinValue[index];
        if (getDigital(index)) {
          pinValue[index] = digitalRead(physicalPin[index]);
        } else {
          // somente ESP8266
          if (pin == A0) {
            pinValue[index] = analogRead(physicalPin[index]);
          } else {
            pinValue[index] = digitalRead(physicalPin[index]);
          }
        }
        // se o novo valor for diferente do anterior marca para enviar.
        if (value != pinValue[index]) {
          if (state == STATE_IDLE) state = STATE_HASDATA;
        }
      }
    }
    return pinValue[index];
  } else {
    return 0xffff;
  }
}

bool MysecDeviceState::setValue(uint8_t pin, float value) {
  uint8_t index = 10;
  for (int i = 0; i < numPins; i++) {
    if (pinNumber[i] == pin) {
      index = i;
      break;
    }
  }
  if (index < numPins) {
    // se for um pino de entrada automático ignora pois o valor é lido diretamente do pino
    if (getAutomatic(index) && !getOutput(index)) {
      return false;
    }
    // é input, não é automático ou é output, está configurado e está dentro do range
    uint16_t newValue = (uint16_t)(value + 0.5);
    if (newValue != pinValue[index]) {
      if (state == STATE_IDLE) state = STATE_HASDATA;
    }
    pinValue[index] = newValue;
    if (getAutomatic(index)) {
      // sendo automático e output, aplica o valor
      if (getDigital(index)) {
        digitalWrite(physicalPin[index], newValue);
      } else {
        analogWrite(physicalPin[index], newValue);
      }

    }
    return true;
  } else {
    return false;
  }
}
bool MysecDeviceState::resetValue(uint8_t pin, float value) {
  uint8_t index = 10;
  for (int i = 0; i < numPins; i++) {
    if (pinNumber[i] == pin) {
      index = i;
      break;
    }
  }
  if (index < numPins) {
    if (!getOutput(index)) {
      return false;
    }
    // é output
    uint16_t newValue = (uint16_t)(value + 0.5);
    if (newValue != pinValue[index]) {
      if (state == STATE_IDLE) state = STATE_HASDATA;
    }
    pinValue[index] = newValue;
    return true;
  } else {
    return false;
  }
}
void MysecDeviceState::applyNext(uint8_t index) {
#if MYSECSWITCH_DEBUG>1
  String p; p.reserve(50);
  p.concat(FPSTR("DeviceState ApplyNext Novo valor "));
  p.concat(pinNextValue[index]);
  p.concat(FPSTR(" no pino "));
  p.concat(pinNumber[index]);
  MYSECSWITCH_DEBUGLN(p.c_str());
#endif
  when[index] = 0;
  pinValue[index] = pinNextValue[index];
  setNextValueSet(index, false); // sinaliza que já aplicou
  if (_mysecUdpNet.isDesabilitaAutomatico()) {
    // desabilitado
    return;
  }
  if (tempoLigado[index] > 0 && tempoDesligado[index] > 0) {
    long tempo;
    // se é intermitente, programa a próxima mudança
    if (pinValue[index]) {
      pinNextValue[index] = LOW;
      tempo = tempoLigado[index] * 60 * 1000; // transforma em milissegundos.
    } else {
      pinNextValue[index] = HIGH;
      tempo = tempoDesligado[index] * 60 * 1000; // transforma em milissegundos.
    }
    setNextValueSet(index, true);
    long desv = tempo / 6;
    desv = tempo + random(0, desv) - desv / 2;
    when[index] = millis() + desv;
  }
  if (getAutomatic(index)) {
    // se for automático, aplicamos o valor no pino.
#if MYSECSWITCH_DEBUG>1
  String p; p.reserve(50);
  p.concat(FPSTR("DeviceState ApplyNext Aplicando valor "));
  p.concat(pinNextValue[index]);
  p.concat(FPSTR(" no pino "));
  p.concat(pinNumber[index]);
  MYSECSWITCH_DEBUGF(F("%s\n"), p.c_str());
#endif
    if (getDigital(index)) {
      digitalWrite(physicalPin[index], pinValue[index]);
    } else {
      analogWrite(physicalPin[index], pinValue[index]);
    }
  }
}

MysecDeviceState _mysecDeviceState;
