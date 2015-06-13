#!/usr/bin/env python
# -*- coding: utf-8 -*-
# =============================================================================
#     FileName: atk_map.py
#         Desc: 2015-15/3/18:上午11:50
#       Author: 苦咖啡
#        Email: voilet@qq.com
#     HomePage: http://blog.kukafei520.net
#      History: 
# =============================================================================
import time
from websocket import create_connection
import pygeoip
import json

def map_data(data, ip, service_addr):
    """
    向websocket发送数据，通知响应
    :return:
    """

    gi = pygeoip.GeoIP('GeoLiteCity.dat', pygeoip.MEMORY_CACHE)
    ws = create_connection("ws://127.0.0.1:8001/websocket")

    # print i.ip
    """
    'latitude': '31.22', 'longitude': '121.47', 为攻击者的坐标
    country 攻击来源
    country2 攻击目标
    {"latitude":"51.00","longitude":"9.00","countrycode":"DE","country":"DE","city":"","org":"Hetzner Online AG - Virtualisierung","latitude2":"47.61","longitude2":"-122.33","countrycode2":"US","country2":"US","city2":"Seattle","type":"ipviking.honey","md5":"78.47.106.229","dport":"50509","svc":"50509","zerg":""}
    """
    s = {'city': '江苏', 'dport': '80', 'countrycode': 'CN', 'country': 'bj11', 'latitude2': 39.93, 'longitude2': 116.39, 'latitude': '31.22', 'longitude': '121.47', 'svc': 'http', 'country2': 'CN', 'city2': '南宁机房', 'countrycode2': 'US',  'hostip': '123.125.2.2', 'zerg': '111111', 'type': data["atk_type"], 'md5': '210.78.137.6'}

    rst = gi.record_by_addr(ip)

    try:
        s["city"] = data["city"]
        s["countrycode"] = rst.get("country_code")
        s["country"] = rst["time_zone"]
        s["country2"] = "beijing"
        s["countrycode2"] = "CN"
        s["city2"] = service_addr
        s["md5"] = data["atk_ip"]
        s["hostip"] = data["idc_server"]
        s["latitude"] = rst["latitude"]
        s["longitude"] = rst["longitude"]
        ws.send(json.dumps(s))
        ws.recv()
    except:
        pass
    time.sleep(0.1)
    ws.close()

    return True