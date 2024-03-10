# DIY AirTag Sniffer

Detect DIY airtags locally from a linux based system (e.g. Raspberry). This can be useful for indoor locating. This 
is intended to work with DIY airtags as there is no support for rotation of keys.

The project works together with my Web UI implementation for AirTags (FindMyGUI) using a MQTT server. If the two apps 
shall communicate you must setup a MQTT server.

This is based on various great projects on github:

https://github.com/biemster/FindMy
https://github.com/seemoo-lab/openhaystack/


## Initial Setup and Configuration

Clone the project from github:

```bash
git clone https://github.com/liebrandapps/DIYAirTagSniffer
```

Install packages in your OS:

```bash
apt install libglib2.0-dev
```

Depending on your linux installation more packages maybe required

For this project, you need python 3 and some dependencies:

```bash
pip3 install -r ./requirements.txt
```

## Disclaimer

Use this application at your own risk! U No guarantee that this application
works at all times and is a fit for a certain purpose.

Links were valid at time of writing this readme. I am not taking any responsible for the linked content.


## Configuration

The app works without any configuration using default values. However, you will only see detected devices in the log 
file (/tmp) or on stdout when not running as daemon.

```bash
[mqtt]
enable=true
server=<YOU MQTT SERVER>
port=<YOUR PORT>
user=
password=
# don't log any received mqtt messages
silent=True
```



## Usage

Run as daemon (start / stop / status)

```bash
python3 main.py start
```
If you start the app w/o parameters, output is directed to the console as well. Default log location is /tmp.



