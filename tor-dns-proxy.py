#!/usr/bin/env python
#
# tor-dns-proxy.py
#
# Proxy nameserver to relay name lookups to Tor.
# Just add a 'nameserver 127.0.0.1' line to /etc/resolv.conf
# ahead of any other nameservers to prevent DNS leaks...
#
# Copyright (c) 2005 Dug Song <dugsong@monkey.org>
#
# $Id: tor-dns-proxy.py,v 1.2 2005/02/28 18:22:26 dugsong Exp $

import optparse, socket, struct, sys, SocketServer
import dpkt

tor_socket = ("127.0.0.1", 9050)
my_socket = ("127.0.0.1", 53)

class DNSHandler:
    def handle_dns(self, buf):
        dns = dpkt.dns.DNS(buf)
        name = dns.qd[0].name
        
        if dns.qd[0].cls == dpkt.dns.DNS_IN: # XXX - ignore type
            # Send Tor SOCKS RESOLVE request.
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(tor_socket)
            buf = struct.pack('>BBHI', 4, 0xF0, 0, 1) + '\x00%s\x00' % name
            s.send(buf)
            # Get Tor SOCKS reply.
            v, stat, port, ip = struct.unpack('>BBH4s', s.recv(1024))
        else:
            stat = -1
        
        # Send DNS reply.
        dns.qr = dpkt.dns.DNS_R
        if stat != 90:
            dns.rcode = dpkt.dns.DNS_RCODE_SERVFAIL
            print '%s -> FAILURE' % name
        else:
            dns.an = [ dpkt.dns.DNS.RR(name=name, rdata=ip) ]
            print '%s -> %s' % (name, socket.inet_ntoa(ip))
        
        self.reply_dns(str(dns))
        
class TcpDNSHandler(DNSHandler, SocketServer.StreamRequestHandler):
    def handle(self):
        # Get DNS request.
        buf = self.rfile.read()
        self.handle_dns(buf[2:])
    def reply_dns(self, buf):
        self.wfile.write(struct.pack('>H', len(buf)) + buf)

class UdpDNSHandler(DNSHandler, SocketServer.DatagramRequestHandler):
    def handle(self):
        # Get DNS request.
        buf = self.rfile.read()
        self.handle_dns(buf)
    def reply_dns(self, buf):
        self.wfile.write(buf)

if __name__ == '__main__':
    op = optparse.OptionParser(usage='usage: %prog [-t]')
    op.add_option('-t', dest='use_tcp', action='store_true', help='use TCP')
    opts, args = op.parse_args(sys.argv[1:])

    if opts.use_tcp:
        Server = SocketServer.ThreadingTCPServer
        Handler = TcpDNSHandler
    else:
        Server = SocketServer.ThreadingUDPServer
        Handler = UdpDNSHandler
    
    server = Server(my_socket, Handler)
    print >>sys.stderr, 'listening on port %d' % my_socket[1]
    server.serve_forever()
