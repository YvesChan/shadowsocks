#!/usr/bin/env python

# Copyright (c) 2012 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys

try:
    import gevent, gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)
except ImportError:
    gevent = None
    print >>sys.stderr, 'warning: gevent not found, using threading instead'

import socket
import select
import SocketServer
import struct
import string
import hashlib
import os
import json
import logging
import getopt

def get_table(key):
    m = hashlib.md5()
    m.update(key)
    s = m.digest()
    (a, b) = struct.unpack('<QQ', s)
    table = [c for c in string.maketrans('', '')]
    for i in xrange(1, 1024):
        table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
    return table

def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent

class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):   # Multiple inheritance
    allow_reuse_address = True


class Socks5Server(SocketServer.StreamRequestHandler):
    ''' RequesHandlerClass Definition '''
    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])      # use select I/O multiplexing model
                if sock in r:                               # if local socket is ready for reading
                    data = sock.recv(4096)
                    if len(data) <= 0:                      # received all data
                        break
                    result = send_all(remote, self.encrypt(data))   # send data after encrypting
                    if result < len(data):
                        raise Exception('failed to send all data')

                if remote in r:                             # remote socket(proxy) ready for reading
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break
                    result = send_all(sock, self.decrypt(data))     # send to local socket(application)
                    if result < len(data):
                        raise Exception('failed to send all data')
        finally:
            sock.close()
            remote.close()

    def encrypt(self, data):
        return data.translate(encrypt_table)

    def decrypt(self, data):
        return data.translate(decrypt_table)

    def send_encrypt(self, sock, data):
        sock.send(self.encrypt(data))

    def handle(self):
        try:
            sock = self.connection        # local socket [127.1:port]
            sock.recv(262)                # Sock5 Verification packet
            sock.send("\x05\x00")         # Sock5 Response: '0x05' Version 5; '0x00' NO AUTHENTICATION REQUIRED
            # After Authentication negotiation
            data = self.rfile.read(4)     # Forward request format: VER CMD RSV ATYP (4 bytes)
            mode = ord(data[1])           # CMD == 0x01 (connect)
            if mode != 1:
                logging.warn('mode != 1')
                return
            addrtype = ord(data[3])       # indicate destination address type
            addr_to_send = data[3]
            if addrtype == 1:             # IPv4
                addr_ip = self.rfile.read(4)            # 4 bytes IPv4 address (big endian)
                addr = socket.inet_ntoa(addr_ip)
                addr_to_send += addr_ip
            elif addrtype == 3:           # FQDN (Fully Qualified Domain Name)
                addr_len = self.rfile.read(1)           # Domain name's Length
                addr = self.rfile.read(ord(addr_len))   # Followed by domain name(e.g. www.google.com)
                addr_to_send += addr_len + addr
            else:
                logging.warn('addr_type not support')
                # not support
                return
            addr_port = self.rfile.read(2)
            addr_to_send += addr_port                   # addr_to_send = ATYP + [Length] + dst addr/domain name + port
            port = struct.unpack('>H', addr_port)       # prase the big endian port number. Note: The result is a tuple even if it contains exactly one item.
            try:
                reply = "\x05\x00\x00\x01"              # VER REP RSV ATYP
                reply += socket.inet_aton('0.0.0.0') + struct.pack(">H", 2222)  # listening on 2222 on all addresses of the machine, including the loopback(127.0.0.1)
                self.wfile.write(reply)                 # response packet
                # reply immediately
                if '-6' in sys.argv[1:]:                # IPv6 support
                    remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                else:
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)       # turn off Nagling
                remote.connect((SERVER, REMOTE_PORT))
                self.send_encrypt(remote, addr_to_send)      # encrypted
                logging.info('connecting %s:%d' % (addr, port[0]))
            except socket.error, e:
                logging.warn(e)
                return
            self.handle_tcp(sock, remote)
        except socket.error, e:
            logging.warn(e)


if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')
    print 'shadowsocks v0.9'

    with open('config.json', 'rb') as f:
        config = json.load(f)
    SERVER = config['server']
    REMOTE_PORT = config['server_port']
    PORT = config['local_port']
    KEY = config['password']

    optlist, args = getopt.getopt(sys.argv[1:], 's:p:k:l:')
    for key, value in optlist:
        if key == '-p':
            REMOTE_PORT = int(value)
        elif key == '-k':
            KEY = value
        elif key == '-l':
            PORT = int(value)
        elif key == '-s':
            SERVER = value

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    encrypt_table = ''.join(get_table(KEY))
    decrypt_table = string.maketrans(encrypt_table, string.maketrans('', ''))
    try:
        server = ThreadingTCPServer(('', PORT), Socks5Server)   # s.bind(('', 80)) specifies that the socket is reachable by any address the machine happens to have.
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error, e:
        logging.error(e)

