from __future__ import with_statement
import os.path
import random
import socket
import sys
import hashlib
from anon_crypto import AnonCrypto
import M2Crypto.RSA
from M2Crypto import Rand

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *


SIZEOF_UINT16 = 2
DEFAULT_PORT = 9000
GUI_PORT = 20000

class Net:
    def __init__(self):
        self.thread = GuiClient()
        self.nodes = []
        self.privKey = ''
        self.pubKey = ''
        self.establish_keys()
        self.establish_peers()

        # get ip and port
        self.ip = self.get_my_ip()
        self.port = self.get_my_port()
        self.debug(str(self.ip) + ":" + str(self.port))

    def establish_peers(self):
        # parse peers if already exist
        if os.path.exists('state'):
            if os.path.isfile('state/peers.txt'):
                self.debug("parsing peers.txt")
                self.nodes = self.parse_peers('state/peers.txt')
                self.debug(str(self.nodes))

        # otherwise, create peers file for later
        else:
            if not os.path.exists('state'):
                os.mkdir('state')
                if not os.path.isfile('state/peers.txt'):
                    self.debug("creating peers.txt")
                    open('state/peers.txt','w').close()

    # load / create pub and priv keys in the config folder	
    def establish_keys(self):
        if not os.path.exists('config'):
            os.mkdir('config')
        try:
            self.load_keys()
        except:
            # generate new keys
            self.debug("keys don't exist/valid")
            newKey = AnonCrypto.random_key(1024)
            self.save_keys(newKey)
            self.load_keys()

    def get_my_ip(self):
        return socket.gethostbyname(socket.gethostname())

    def get_my_port(self):
        try:
            return self.load_port()
        except:
            # generate port file with default
            self.debug("port file doesn't exist, defaulting to " + str(DEFAULT_PORT))
            f = open('config/port', 'w')
            f.write(str(DEFAULT_PORT))
            f.close()
            return DEFAULT_PORT

    def load_port(self):
        with open('config/port') as f:
            for line in f:
                parts = line.split()
                return int(parts[0])

    def parse_peers(self, filename):
        nodes = []
        with open(filename, 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    raise SyntaxError, "Cannot parse node file"
                ip, port = socket.gethostbyname(parts[0]), int(parts[1])
                pubkey = hashlib.sha1("%s" % ((ip,port),)).hexdigest()
                nodes.append((ip,port,pubkey))
        return nodes

    # called by GUI right now -- just for testing purposes
    def testMessage(self):
        self.thread.run("testing")

    def debug(self, msg):
        self.thread.run("<b>Net</b>: " + msg)

    # saves public and private keys to local config directory
    def save_keys(self, rsa_key):
        rsa_key.save_key('config/priv', None)
        rsa_key.save_pub_key('config/pub')

    def load_keys(self):
        self.privKey = M2Crypto.RSA.load_key('config/priv')
        self.pubKey = M2Crypto.RSA.load_pub_key('config/pub')

    # print public key as string		
    def public_key_string(self):
        return AnonCrypto.pub_key_to_str(self.pubKey)

    # print private key as string
    def private_key_string(self):
        return AnonCrypto.priv_key_to_str(self.privKey)

class GuiClient(QThread):
    def __init__(self, parent = None):
        super(GuiClient, self).__init__(parent)
        self.socket = QTcpSocket()
        self.nextBlockSize = 0
        self.request = None

    # called by thread
    def run(self, msg):
        self.issueRequest(QString(msg))

    # package msg into stream, send to GUI
    def issueRequest(self, msg):
        self.request = QByteArray()
        stream = QDataStream(self.request, QIODevice.WriteOnly)
        stream.setVersion(QDataStream.Qt_4_2)
        stream.writeUInt16(0)
        stream << msg
        stream.device().seek(0)

        # prepend number of bits
        stream.writeUInt16(self.request.size() - SIZEOF_UINT16)
        if self.socket.isOpen():
            self.socket.close()
        self.socket.connectToHost("localhost", GUI_PORT)
        self.sendRequest()

    # send to GUI
    def sendRequest(self):
        self.nextBlockSize = 0
        self.socket.write(self.request)
        self.socket.waitForBytesWritten(1000)
        self.request = None
        self.socket.close()
