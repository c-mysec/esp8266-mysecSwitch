/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * MysecDeviceState.h
 *
 *  Created on: 23 de dez de 2016
 *      Author: user2
 */

#ifndef MYSECDEVICESTATE_H_
#define MYSECDEVICESTATE_H_

#include "depend/MysecParser.h"

#ifndef DEF_NUMPINS
#define DEF_NUMPINS 8
#endif

class MysecDeviceState {
public:
  enum MYSEC_STATE : int8_t { STATE_DISCONNECTED, STATE_CONNECTING, STATE_IDLE, STATE_HASDATA};
  enum MYSEC_TYPE : int8_t { TYPE_HTTP, TYPE_WEBSOCKET};
  MysecParser* mysecParser;
  String pb2;
  uint64_t timeoffset = 0;
  uint32_t lasttimeMillis = 0;
  uint32_t lastSynch = 0;
  uint32_t lastSynchOk = 0;
  String url;
  uint64_t id = 0;
  uint32_t tag1 = 1;
  uint32_t tag2 = 1;
  uint8_t passkey2[32];
  uint8_t passkey1[32];
  uint8_t nextPk1[32];
  uint8_t nextPb1[32];

  uint8_t pinNumber[DEF_NUMPINS];
  uint8_t physicalPin[DEF_NUMPINS];
  double pinValue[DEF_NUMPINS];
  double pinNextValue[DEF_NUMPINS];
  uint32_t when[DEF_NUMPINS]; // quando vai mudar para o pinNextValue, valor ajustado para o millis() local em segundos.
  int8_t tempoLigado[DEF_NUMPINS]; // zero indica que não é intermitente -- em minutos, < 0 eh manual
  int8_t tempoDesligado[DEF_NUMPINS]; // zero indica que não é intermitente -- em minutos
  // 0-nextValueset, 1-output, 2-digital, 3-automatic
  uint8_t pinFlags[DEF_NUMPINS];
  uint8_t flags = 0;
  uint8_t numPins = 0;
  uint8_t numHttpErrors = 0;
  MYSEC_STATE state = STATE_DISCONNECTED;
  MYSEC_TYPE connType = TYPE_WEBSOCKET;
  MysecDeviceState(){
    mysecParser = new MysecParser();
    memset(nextPk1, 0, 32);
    memset(nextPb1, 0, 32);
  };
  ~MysecDeviceState(){
    delete mysecParser;
  };
  void setNextSynch();
  void setNextValueSet(uint8_t pin, bool f);
  bool getNextValueSet(uint8_t pin);
  void setOutput(uint8_t pin, bool f);
  bool getOutput(uint8_t pin);
  void setDigital(uint8_t pin, bool f);
  bool getDigital(uint8_t pin);
  void setAutomatic(uint8_t pin, bool f);
  bool getAutomatic(uint8_t pin);
  void applyNext(uint8_t index);
  /**
   * Insere uma nova configuração para um pino. Deve ser executado uma única vez para cada pino.
   * Parâmetro Automatico quando TRUE indica que o pino será gerenciado pela API. Assim, no caso de
   * input/entrada, a API irá acionar digitalRead ou analogRead e no caso de saída, a API irá acionar digitalWrite
   * e analogWrite quando receber um comando do servidor. Se Automatico for FALSE então a API apenas irá armazenar o valor
   * e devolver quando a aplicação chamar o método getValue().
   * O modo não automático é interessante quando se quer fazer um processamento para chegar ao valor a ser enviado ao servidor ou
   * vice-versa.
   * PinNumber é o número do pino configurado no servidor e geralmente é aquele pelo qual o pino é conhecido e estampado na placa.
   * physicalPin é o número de acesso pela API. Exemplos: D1, D2, A0.
   * Retorna false se o pino já estiver configurado ou se passou do limite de 8 pinos.
   */
  bool setupPin(uint8_t pinNumber, bool output, bool digital, bool automatic, uint8_t physicalPin);
  /**
   * Informa para a API o valor de um pino de input/entrada que não é automático (onde a api não lê o pino diretamente).<br>
   * Se um pino for de saída, avisa o servidor que o pino mudou como se fosse um pino de entrada e ser for automático, aplica o novo valor no pino.
   */
  bool setValue(uint8_t pinNumber, double pinValue);
  /**
   * Para um pino do tipo output, informa o valor atual (ou que deveria ser atual).<br>
   * No modo automático, a API ajusta o valor do pino automaticamente (digitalWrite ou analogWrite),
   * mas a API não fica forçando o valor (o comando de alterar o valor no pino é executado uma única vez, caso
   * algum outro código alterar o valor depois, a API não saberá).<br>
   * retorna 0xffff caso não seja um pino configurado.
   */
  double getValue(uint8_t pinNumber);
  /**
   * Força o valor da variável interna. Útil para pinos que não são automáticos e precisam de um comando único.
   * Deve ser chamado após o getValue. Assim, não lerá o comando 2 vezes.
   * Só tem efeito para pino do tipo Output.
   */
  bool resetValue(uint8_t pinNumber, double pinValue);
  void updateValues();
};
extern MysecDeviceState _mysecDeviceState;
#endif /* MYSECDEVICESTATE_H_ */
