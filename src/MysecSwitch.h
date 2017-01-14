/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * MysecSwitch.h
 *
 *  Created on: 23 de dez de 2016
 *      Author: user2
 */

#ifndef MYSECSWITCH_H_
#define MYSECSWITCH_H_


#define INPUT_UPDATE_INTERVAL  1800000
#define OUTPUT_UPDATE_INTERVAL  120000

class MysecSwitch {
private:
  bool processaChaveNova();
  void persisteChaves();
  void processaUdp();
  void conectaServidorCentral();
public:
  MysecSwitch() {
  };
  ~MysecSwitch() {
  }

  /**
   * id is the device id on MySec
   */
  void init(const char * centralServerURL, uint64_t id, int port, bool integraAlarme, const char * passk2);
  void init(const char * centralServerURL, uint64_t id, int port, bool integraAlarme, const uint8_t * passk2);
  String getLastSynchTime();
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
  bool setValue(uint8_t pinNumber, float pinValue);
  /**
   * Para um pino de input retorna o valor atual na api. Caso o pino de input seja automático, primeiro atualiza o valor da api lendo o pino físico.
   * Para um pino do tipo output, informa o valor atual (ou que deveria ser atual).<br>
   * No modo automático, a API ajusta o valor do pino automaticamente (digitalWrite ou analogWrite),
   * mas a API não fica forçando o valor (o comando de alterar o valor no pino é executado uma única vez, caso
   * algum outro código alterar o valor depois, a API não saberá).<br>
   * retorna 0xffff caso não seja um pino configurado.
   */
  uint16_t getValue(uint8_t pinNumber);
  /**
   * Força o valor da variável interna. Útil para pinos que não são automáticos e precisam de um comando único.
   * Deve ser chamado após o getValue. Assim, não lerá o comando 2 vezes.
   * Só tem efeito para pino do tipo Output.
   */
  bool resetValue(uint8_t pinNumber, float pinValue);
  /**
   * Verifica se tem alguma programação ara aplicar e verifica se pode realizar uma nova sincronização com o servidor.
   */
  void loop();

};

#endif /* MYSECSWITCH_H_ */
