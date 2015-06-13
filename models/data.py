#!/usr/bin/env python
# -*- coding: utf-8 -*-
# =============================================================================
#     FileName: data.py
#         Desc: 2015-15/3/9:下午4:55
#       Author: 苦咖啡
#        Email: voilet@qq.com
#     HomePage: http://blog.kukafei520.net
#      History: 
# =============================================================================

from mongoengine import *
from datetime import datetime

class hacker_data(Document):
    atk_ip = StringField(max_length=50, required=True)
    city = StringField()
    addr = StringField()
    url = StringField()
    idc_server = StringField()
    user_agent = StringField()
    acl = StringField()
    method = StringField()
    data = StringField()
    atk_time = DateTimeField()
    script = StringField()
    atk_type = StringField()
    ip_data = StringField()
    domain = StringField()
    datetime = DateTimeField(default=datetime.now())