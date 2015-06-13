#!/usr/bin/env python
# -*- coding: utf-8 -*-
# =============================================================================
#     FileName: syslog_service.py
#         Desc: 2015-15/3/9:下午2:38
#       Author: 苦咖啡
#        Email: voilet@qq.com
#     HomePage: http://blog.kukafei520.net
#      History: 
# =============================================================================


from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from models.atk import search


from QQWry import IPSearch

#初始化ip库
tt = IPSearch('qqwry.dat')

#上报服务器域名或IP



class MulticastPingPong(DatagramProtocol):

    def startProtocol(self):
        self.transport.setTTL(5)
        self.transport.joinGroup("228.0.0.5")

    def datagramReceived(self, datagram, address):
        print datagram
        data = search(datagram)
        return data
        # return True
def main():
    reactor.listenMulticast(5144, MulticastPingPong(), listenMultiple=True)
    reactor.run()

if __name__ == '__main__':
    main()

