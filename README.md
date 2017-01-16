# ESP8266-mysecSwitch
A Library to control ESP8266 using Mysec website and MysecSwitch Android App (remote and local without a server).

With ESP8266-mysecSwitch library you can control and monitor you ESP8266 IOT device in many ways.

1. From anywhere with Internet connection using
   * Mysec website
   * MysecSwitch Android App (a viewer)
2. Directly (without any server) from your local-area-network using
   * MysecSwitch Android App (a viewer)

With ESP8266-mysecSwitch all messages exchanged between two entities (web server, android and iot devices) are signed with HMAC-SHA256.
HMAC-SHA256 session keys are generated using Curve25519 key exchange and they are re-created frequently.

ESP8266-mysecSwitch also integrate into Mysec WifiAlarm system events (activation, deactivation and fired), activating  everything on intrusion detection for example.
## Concepts
To use this library you need first to register on https://www.thinkingthing.space/mysec for free.

At Mysec Webite you can register all your IOT devices.

Every device can have virtual pins. A virtual pin can be for INPUT (sensor pin) or OUTPUT (control pin).

For INPUT type virtual pin, data flow from your sensor to ESP8266 device to Website then to a Viewer.

For OUTPUT type virtual pin, data flow from your ESP8266 device to Website then to a Viewer and also in the reverse direction.

When your viewer is at the same LAN as the ESP8266 device the viewer connects directly to the device and data flow from the sensor to the ESP8266 to the viewer.

**why bi-directional communication for OUTPUT type pin?**

Because a Viewer can control ESP8266 devices directly when at the same LAN, the Webserver has to be notified about changes made from the viewer and the Viewer has to be notified about change made from the web. Also, you can also change pin state from your sketch and both viewer and website have to be updated.

**Virtual pins**

A virtual pin is a value to be controled or monitored. A virtual pin can be directly associated with an ESP8266 GPIO pin, but it does not need to be.

Every virtual pin has a pin number that is used to identify the virtual pin. This virtual pin number is not related to the physical pin number (or GPIO number), it is only an identification of the virtual pin in the system.

A simple virtual pin can be directly associated with a physical GPIO.

A virtual pin assigned with a GPIO pin number can be set to be controled/monitored automatically by the library, meaning that commands sent from viewer or website will be automatically flow to the physical ESP8266 GPIO pin and values will be read automatically from ESP8266 GPIO physical pin for an INPUT virtual pin.

For an OUTPUT virtual pin not set to be controled automatically by the library, your sketch needs to periodically read commands from the library.

For an INPUT virtual pin not set to be monitored automatically by the library, your sketch needs to update the library when monitored values changes.

As a plus, for automatic OUTPUT pins, at Mysec Website you can program timers to automate changes virtual pin state.

## Installation
To use this library you need an Arduino Ide environment and libraries and Arduino core for ESP8266 WiFi chip.

If you don't know arduino, see [here](https://github.com/esp8266/Arduino).

Then you need to install this library and the dependencies.

To install ESP8266-mysecSwitch library download the repository code (clone or download button and then download zip) and then include in the Arduino IDE libraries (see [here](https://www.arduino.cc/en/Guide/Libraries) for a guide).

You also need to install these two dependencies:

1. [ArduinoJson](https://github.com/bblanchon/ArduinoJson)
2. [Curve25519_ESP8266](https://github.com/c-mysec/Curve25519_ESP8266)

## Usage

*see the sample sketches in the repository for an overview.*

1. Import the library
    ```#include <MysecSwitch.h>```
2. Create instances of Wifi and MysecSwitch
    ```
    ESP8266WiFiMulti wifiMulti;
    MysecSwitch dev;
    ```
3. Setup <b>Internet</b> connection
    ```
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);
    wifiMulti.addAP(wifiSSID, wifiPasswd);
	Serial.println("\nConnecting Wifi...");
    while (wifiMulti.run() != WL_CONNECTED && millis() < 60000) { // 60 segundos para conectar
      delay(500);
      Serial.print(".");
    }
    ```
4. If successfully connected to Wifi, then setup Mysec device (this must match configuration at Mysec Website)
    ```
    // Setup MysecSwitch library
    // url      -> URL for the Mysec Website, it has to be "http://thinkingthing.space/mysec"
    // id       -> ID for the device given by Mysec Website
    // port     -> UDP port for local LAN connection with a viewer
    // true     -> set to true if you want this device to respond to Mysec Alarm events
    // passkey2 -> Device passkey generated by Mysec Website, this passkey is used the first time your device connects with the server. If after initialization, you pass a different passkey next time, the library will think you want to reset criptographic keys and performa a new initialization when connecting with the server and other devices.
    dev.init(url, id, port, true, passkey2);
    ```
5. Setup physical GPIO pin
    ```
    // In this example we have 1 OUTPUT virtual pin, it is connected to GPIO-2.
    // D4 is the "NodeMCU/Wemos D1 mini" label on the printed circuit and is equivalent to GPIO-2 (D4 constant value is 2).
    // On Wemos D1 mini, this pin is connected to a built in LED. Note that a LOW signal on this pin turns the LED ON.
    pinMode(D4, OUTPUT); // can be replaced by pinMode(2, OUTPUT);
    ```
6. Setup Mysec Virtual pin (this must match configuration at Mysec Website)
    ```
    // Setup pin number 1. Parameter details:
    // 1                    -> indentify this pin as pin number 1 (the same number has to be configured at Mysec Website)
    // true /* output */    -> this is an OUTPUT pin
    // true /* digital */   -> this pin only accepts true/false (0/1) values.
    // true /* automatic */ -> commands received from viewer or Mysec Website will be automatically applied to physical GPIO-2.
    // D4                   -> Physical pin, needed only with automatic pins.
    dev.setupPin(1, true /*output*/, true /*digital*/, true/*automatic*/, D4/*physical pin*/);
    ```
7. Let MysecSwitch work for you
    ```
    void loop() {
      dev.loop();
    }
    ```

**Non-automatic virtual pins**

This library can automatically manage (monitor or control) a value that can be directly applied or read from a physical GPIO (a digital value or an integer value between 0 and 1023). For example, suppose you have an intruder detection system, on of the virtual pins should be the sensor id. The sensor id is a complex value since it has to be calculated by your code and thus cannot be automatically controled by the library.

If you have virtual pins which are not automatically controlled by the library you need to notify the library of changes (for INPUT virtual pins) and you need get new values (or commands) from the library and apply them.

For example, to monitor a DTH22 temperature sensor you need to use a library designed specifically to that sensor. Probably you have something like this:
1. Create instances
    ```
    DHT dht(DHTPIN, DHTTYPE);
    MysecSwitch dev;
    ```
2. Setup DHT API
    ```
    dht.begin
    ```
3. Setup an analog non-automatic virtual pin
    ```
    dev.init(url, id, port, true, passkey2);
    dev.setupPin(1, false /*input*/, false /*analog*/, false/*not automatic*/, 0/*no physical pin*/);
    dev.setupPin(2, false /*input*/, false /*analog*/, false/*not automatic*/, 0/*no physical pin*/);
    ```
4. Acquire the complex value
    ```
    float h = dht.readHumidity();
    float f = dht.readTemperature(true);
    ```
5. Inform mysecSwitch API with the new value
    ```
    dev.setValue(1, h);
    dev.setValue(3, f);
    ```

