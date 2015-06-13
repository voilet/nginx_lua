#!/usr/bin/env python
# -*- coding: utf-8 -*-
# =============================================================================
#     FileName: atk.py
#         Desc: 2015-15/3/9:下午4:13
#       Author: 苦咖啡
#        Email: voilet@qq.com
#     HomePage: http://blog.kukafei520.net
#      History: 
# =============================================================================
from mongoengine import *
import ast
from acl.rule import atk
from QQWry import IPSearch
from models.data import hacker_data
from models.atk_map import map_data
import datetime
#初始化ip库
tt = IPSearch('qqwry.dat')
connect("hacker_atk", host="192.168.115.205", port=27017)
def search(datagram):
    """
    :param data:
    :param ip:
    :return:
    """
    # print datagram
    data = datagram.split("")

    ip_data = data[0].split(",")
    if len(ip_data) > 1:
        idc = ip_data[1]
    else:
        idc = '-'
    hack_search = tt.find(ip_data[0])
    hack_city = unicode(hack_search[0], 'gb2312').encode('utf-8')
    if hack_search[1] != "":
        hack_city_addr = unicode(hack_search[1], 'gb2312').encode('utf-8')
    else:
        hack_city_addr = "-"

    atk_roul = data[-1].strip()
    if data[2].strip() == "UA":
        atk_type = "黑客扫描"
    else:
        atk_type = atk(atk_roul.strip())
    service = tt.find(idc)
    service_addr = unicode(service[0], 'gb2312').encode('utf-8')

    print "攻击IP:", ip_data[0]
    print "攻击机房:", idc, service_addr
    print "黑客所在地", hack_city, hack_city_addr
    print "攻击域名:", data[3]
    print "攻击url:", data[4]
    print "user-agent:", data[-2]
    print "匹配规则:", data[-1]
    print "攻击方式:", data[2]
    print "攻击时间:", data[1]
    print "提交数据:", data[5]
    print "攻击节点", data[0]
    print "-" * 100
    print ""
    print ""
    atk_data = {}
    try:
        db = hacker_data()
        db.atk_ip = ip_data[0].strip()
        db.idc_server = idc.strip()
        db.city = hack_city.strip()
        db.addr = hack_city_addr.strip()
        db.url = data[4].strip()
        db.user_agent = data[-2].strip()
        db.domain = data[3].strip()
        db.acl = data[-1].strip()
        db.method = data[2].strip()
        db.atk_time = data[1].strip()
        db.data = data[5].strip()
        db.atk_type = atk_type.strip()
        db.ip_data = data[0].strip()
        db.datetime = datetime.datetime.now()
        db.save()
    except:
        db = hacker_data()
        db.atk_ip = ip_data[0].strip()
        db.idc_server = idc.strip()
        db.city = hack_city.strip()
        db.addr = hack_city_addr.strip()
        db.url = data[4].strip()
        db.user_agent = data[-2].strip()
        db.domain = data[3].strip()
        db.acl = data[-1].strip()
        db.method = data[2].strip()
        db.atk_time = data[1].strip()
        db.data = ""
        db.atk_type = atk_type.strip()
        db.ip_data = data[0].strip()
        db.datetime = datetime.datetime.now()
        db.save()
    atk_data["city"] = hack_city.strip()
    atk_data["atk_ip"] = ip_data[0].strip()
    atk_data["idc_server"] = idc.strip()
    atk_data["addr"] = hack_city_addr.strip()
    atk_data["atk_type"] = atk_type.strip()
    map_data(atk_data, ip_data[0], service_addr)
    return True
