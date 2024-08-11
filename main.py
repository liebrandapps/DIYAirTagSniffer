"""
  Mark Liebrand 2024
  This file is part of DIYAirTagSniffer which is released under the Apache 2.0 License
  See file LICENSE or go to for full license details https://github.com/liebrandapps/DIYAirTagSniffer
"""
import base64
import glob
import json
import logging
import secrets
import signal
import sys
from datetime import datetime
from hmac import HMAC
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from logging.handlers import RotatingFileHandler
from os import makedirs, chmod
from os.path import join, exists, splitext
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlparse

from airTag import AirTag
from config import Config
from context import Context
from daemon import Daemon
from mqtt import MQTT
from bluepy import btle
from bluepy.btle import Scanner, Peripheral, Characteristic, ScanEntry, UUID
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import uuid

APP = "DIYAirTagSniffer"
CONFIG_DIR = "./"
CONFIG_FILE = "diyairtagsniffer.ini"


def setupLogger():
    global runAsDaemon
    try:
        _log = logging.Logger(APP)
        loghdl = RotatingFileHandler(cfg.logging_logFile, 'a', cfg.logging_maxFilesize, 4)
        loghdl.setFormatter(logging.Formatter(cfg.logging_msgFormat))
        loghdl.setLevel(cfg.logging_logLevel)
        _log.addHandler(loghdl)
        if cfg.logging_stdout and not runAsDaemon:
            loghdl = logging.StreamHandler(sys.stdout)
            loghdl.setFormatter(logging.Formatter(cfg.logging_msgFormat))
            loghdl.setLevel(cfg.logging_logLevel)
            _log.addHandler(loghdl)
        _log.disabled = False
        return _log
    except Exception as e:
        print("[%s] Unable to initialize logging. Reason: %s" % (APP, e))
        return None


def terminate(sigNo, _):
    global doTerminate
    global myServer
    global httpIsRunning
    if doTerminate:
        return
    doTerminate = True
    mqtt.publish(ctx.cfg.general_topic, "{ 'op': 'terminating' }")
    ctx.log.info(f"[{APP}] Terminating with Signal {sigNo} {sigs[sigNo]}")


def loadAirTags():
    global ctx
    airTagDir = ctx.cfg.general_airTagDirectory
    airTagSuffix = ctx.cfg.general_airTagSuffix
    if not exists(airTagDir):
        ctx.log.info(
            f"[loadAirTags] Airtags Directory '{airTagDir}' does not exist, creating it. This will be used to store "
            f"Airtag key information.")
        makedirs(airTagDir)
    tags = glob.glob(join(airTagDir, '*' + airTagSuffix))
    for t in tags:
        airtag = AirTag(ctx, jsonFile=t)
        ctx.airtags[airtag.id] = airtag


def getKey():
    global ctx
    keyDir = ctx.cfg.general_keyDirectory
    credFile = join(keyDir, "creds.json")
    if not exists(keyDir):
        ctx.log.info(
            f"[getKeys] Key Directory '{keyDir}' does not exist, creating it. This will be used to store key information.")
        makedirs(keyDir)
    if exists(credFile):
        ctx.log.info(f"[getKey] Loading credentials from file '{credFile}")
        with open(credFile, "r") as f:
            dct = json.load(f)
        ctx.aesKey = dct['aes']
        ctx.uid = dct['uid']
    else:
        ctx.log.info(f"[getKey] Creating credentials and saving to file '{credFile}")
        uid = str(uuid.uuid4())
        aesKey = secrets.token_hex(32)
        dct = {'uid': uid, 'aes': aesKey}
        with open(credFile, 'w') as f:
            json.dump(dct, f)
        ctx.aesKey = aesKey
        ctx.uid = uid


def mqttCBKeyResponse(topic, payload):
    global ctx, responseTopic, cfg
    jsn = json.loads(payload)
    print(jsn)
    key = RSA.import_key(base64.b64decode(jsn['publicKey']))
    cipher_rsa = PKCS1_OAEP.new(key)
    encData = cipher_rsa.encrypt(bytes.fromhex(ctx.aesKey))
    responseTopic = cfg.mqtt_topic + ctx.uid + "/airtag_response"
    resp = {'uid': ctx.uid, 'encData': base64.b64encode(encData).decode('ascii'), 'responseTopic': responseTopic}
    mqtt.subscribe(responseTopic, mqttCBAirTagResponse)
    mqtt.publish(cfg.mqtt_topicFMG + "airtag_request", resp)


def mqttCBAirTagResponse(topic, payload):
    global ctx, responseTopic, cfg
    jsn = json.loads(payload)
    nonce = base64.b64decode(jsn['nonce'])
    cipher = AES.new(bytes.fromhex(ctx.aesKey), AES.MODE_CTR, nonce=nonce)
    encData = base64.b64decode(jsn['encDta'])
    clearData = cipher.decrypt(encData).decode('utf-8')
    jsn = json.loads(clearData)
    if jsn['id'] in ctx.airtags.keys():
        airtag = ctx.airtags[jsn['id']]
        airtag.fromJSON(clearData)
    else:
        airtag = AirTag(ctx, jsonString=clearData)
    if airtag.needsSave:
        airtag.save()
    ctx.airtags[airtag.id] = airtag


if __name__ == '__main__':
    doTerminate = False
    initialConfig = {
        "general": {
            "airTagDirectory": ['String', 'airtags'],
            "keyDirectory": ['String', 'key'],
            "airTagSuffix": ['String', '.json'],
            "history": ["Integer", 30],
            "location": ["String", "Marks Office"],
            "lon": ["Float", 7.4971],
            "lat": ["Float", 46.9756],
            "pidFile": ["String", "/tmp/airtagsniffer.pid"]
        },
        "logging": {
            "logFile": ["String", "/tmp/airtagsniffer.log"],
            "maxFilesize": ["Integer", 1000000],
            "msgFormat": ["String", "%(asctime)s, %(levelname)s, %(module)s {%(process)d}, %(lineno)d, %(message)s"],
            "logLevel": ["Integer", 10],
            "stdout": ["Boolean", True],
        },
        "mqtt": {
            "enable": ["Boolean", False],
            "server": ["String", ],
            "port": ["Integer", 1883],
            "user": ["String", ""],
            "password": ["String", ],
            "keepAlive": ["Integer", 60],
            "subscribeTopic": ["String", None],
            "retainedMsgs": ["Boolean", False],
            "debug": ["Boolean", False],
            "reconnect": ["Integer", 24, "Reconnect every 24 hours"],
            "silent": ["Boolean", False, "If set to true, no received mqtt messages are logged. (Default: False)"],
            "topic": ["String", "airtagSniffer/app/"],
            "topicFMG": ["String", "findmygui/app/"]
        },
        "airtag": {
            "locationUpdate": ["Integer", 3600],
            "scanDuration": ["Integer", 5, "Scan for 5 seconds, then loop"],
        }
    }
    path = join(CONFIG_DIR, CONFIG_FILE)
    if not (exists(path)):
        print(f"[{APP}] No config file {CONFIG_FILE} found at {CONFIG_DIR}, using defaults")
    cfg = Config(path)
    cfg.addScope(initialConfig)
    runAsDaemon = False
    if len(sys.argv) > 1:
        todo = sys.argv[1]
        if todo in ['start', 'stop', 'restart', 'status']:
            runAsDaemon = True
            pidFile = cfg.general_pidFile
            logFile = cfg.logging_logFile
            d = Daemon(pidFile, APP, logFile)
            d.startstop(todo, stdout=logFile, stderr=logFile)
    log = setupLogger()
    if log is None:
        sys.exit(-126)
    ctx = Context(cfg, log)
    ctx.uid = "uid_not_set"

    doTerminate = False
    signal.signal(signal.SIGINT, terminate)
    signal.signal(signal.SIGTERM, terminate)
    sigs = {signal.SIGINT: signal.SIGINT.name,
            signal.SIGTERM: signal.SIGTERM.name}

    mqtt = MQTT(ctx)
    mqtt.start()
    ctx.mqtt = mqtt
    loadAirTags()
    if cfg.mqtt_enable:
        log.info(f"[{APP}] Using MQTT")
        getKey()
        responseTopic = cfg.mqtt_topic + ctx.uid + "/key_response"
        dct = {'uid': ctx.uid, 'responseTopic': responseTopic}
        mqtt.subscribe(responseTopic, mqttCBKeyResponse)
        mqtt.publish(cfg.mqtt_topicFMG + "key_request", dct)

    log.info(f"[{APP}] Start scanning for devices")
    duration = cfg.airtag_scanDuration
    locationUpdate = cfg.airtag_locationUpdate
    unknownTags = {}
    while not doTerminate:
        try:
            scanner = Scanner()
            devices = scanner.scan(duration)
            now = datetime.now()
            foundDevices = 0
            for dev in devices:
                devname = dev.getValueText(btle.ScanEntry.COMPLETE_LOCAL_NAME)
                if devname is None:
                    devname = dev.getValueText(btle.ScanEntry.SHORT_LOCAL_NAME)

                """
                print("scan: Device {} [{}] ({}), Connect={}, RSSI={} dB".format(dev.addr, devname, dev.addrType,
                                                                                 dev.connectable, dev.rssi))
                """
                for (adtype, desc, value) in dev.getScanData():
                    if desc == "Manufacturer" and value[:8] == "4c001219":
                        # print(f"######## AIRTAG FOUND {len(value)}")
                        if len(value) == 58:
                            hexStatus = value[9]
                            hexKey = dev.addr.replace(":", "") + value[10:54]
                            hexTwoBits = value[54:56]
                            bts = bytes.fromhex(hexKey)
                            bt = bytes.fromhex(hexTwoBits)[0]
                            bArray = bytearray(bts)
                            bArray[0] = (bArray[0] & 63) + (bt << 6)
                            b64 = base64.b64encode(bytes(bArray)).decode('ascii')
                            # print(f"full data found (key {b64}")
                            found = False
                            dct = None
                            for airtag in ctx.airtags.values():
                                if b64 == airtag.advertisementKey:
                                    if b64 in unknownTags.keys():
                                        del unknownTags[b64]
                                    if airtag.lastSeen is None or (now - airtag.lastSeen).total_seconds() > locationUpdate:
                                        airtag.lastSeen = now
                                        dct = {'known': True, 'uid': ctx.uid, 'name': airtag.name,
                                               'tagId': airtag.id,
                                               'lat': cfg.general_lat, 'lon': cfg.general_lon,
                                               'location': cfg.general_location,
                                               'timestamp': now.timestamp(),
                                               'status': int(value[8:10], base=16)
                                               }
                                        log.debug(f"Found airtag {airtag.name}")
                                    found = True
                                    break
                            if not found:
                                if b64 not in unknownTags.keys() or (now - unknownTags[b64]).total_seconds() > locationUpdate:
                                    unknownTags[b64] = now
                                    dct = {'known': False, 'uid': ctx.uid, 'advKey': b64,
                                            'lat': cfg.general_lat, 'lon': cfg.general_lon,
                                            'location': cfg.general_location,
                                            'timestamp': now.timestamp(),
                                            'responseTopic': cfg.mqtt_topic + ctx.uid + "/airtag_response"
                                            }
                                    log.debug(f"Found unidentified airtag {b64}")

                            if dct is not None and ctx.aesKey is not None:
                                cipher = AES.new(bytes.fromhex(ctx.aesKey), AES.MODE_CTR)
                                dta = json.dumps(dct)
                                ciphertext = cipher.encrypt(dta.encode('utf-8'))
                                req = {}
                                req['uid'] = ctx.uid
                                req['encDta'] = base64.b64encode(ciphertext).decode('ascii')
                                req['nonce'] = base64.b64encode(cipher.nonce).decode('ascii')
                                mqtt.publish(cfg.mqtt_topicFMG + "location_update", req)

        except Exception as e:
            log.exception("scan: Error")
