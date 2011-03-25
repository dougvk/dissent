from __future__ import with_statement
import os.path
import random
import socket
import sys
import hashlib
import marshal

from anon_crypto import AnonCrypto
from anon_net import AnonNet
import M2Crypto.RSA

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *


SIZEOF_UINT16 = 2
DEFAULT_PORT = 9000
GUI_PORT = 20000
KEY_LENGTH = 1024

class Net:
    def __init__(self):
        self.thread = GuiClient()
        self.nodes = []
        self.privKey = ''
        self.pubKey = ''

        # load up your priv/pub keypair
        self.establish_keys()

        """
        load up your peer array with (ip, port, hashstring) peer tuples
        hashstring will be the public key name of that peer
        saved as state/hashstring.pub
        """
        self.establish_peers()

        # get ip and port
        self.ip = self.get_my_ip()
        self.port = self.get_my_port()
        self.DEBUG(str(self.ip) + ":" + str(self.port))

    # create/load necessary files to save peer state
    def establish_peers(self):
        # parse peers if already exist
        if os.path.exists('state') and os.path.isfile('state/peers.txt'):
            self.DEBUG("parsing peers.txt")
            self.nodes = self.parse_peers('state/peers.txt')
            self.DEBUG(str(self.nodes))
            return

        """
        otherwise, create peers file for later
        debug.txt contains (peername, hashstring) to
        make debugging easier
        """
        if not os.path.exists('state'):
            os.mkdir('state')
        if not os.path.isfile('state/peers.txt'):
            self.DEBUG("creating peers.txt")
            open('state/peers.txt','w').close()
            open('state/debug.txt','w').close()

    # load / create your pub and priv keys in the config folder	
    def establish_keys(self):
        if not os.path.exists('config'):
            os.mkdir('config')
        try:
            # load them into instance vars if they already exist
            self.load_keys()
        except:
            # generate new keys, save them to config/priv
            # and config/pub -- then load them into instance vars
            self.DEBUG("keys don't exist/valid")
            newKey = AnonCrypto.random_key(KEY_LENGTH)
            self.save_keys(newKey)
            self.load_keys()

    # returns ip of host as string
    def get_my_ip(self):
        return socket.gethostbyname(socket.gethostname())

    def get_my_port(self):
        try:
            # if port file exists, return it
            return self.load_port()
        except:
            # generate port file with default value
            self.DEBUG("port file doesn't exist, defaulting to " + str(DEFAULT_PORT))
            f = open('config/port', 'w')
            f.write(str(DEFAULT_PORT))
            f.close()
            return int(DEFAULT_PORT)

    # returns port from file as integer
    def load_port(self):
        with open('config/port') as f:
            for line in f:
                parts = line.split()
                return int(parts[0])

    """
    parses peer.txt for ip and port then
    adds (ip,port,sha1(ip:port)) tuple to nodes.
    the public key of that peer will then be saved
    to state/hashstring.pub
    """
    def parse_peers(self, filename):
        nodes = []
        debug_file = open('state/debug.txt','w')
        with open(filename, 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    raise SyntaxError, "Cannot parse node file"
                ip, port = socket.gethostbyname(parts[0]), int(parts[1])
                pubkey = self.hash_peer(ip, port)
                nodes.append((ip,port,pubkey))
                debug_file.write(parts[0] + " " + pubkey + "\n")
        debug_file.close()
        return nodes

    # returns hash of ip:port peer
    def hash_peer(self, ip, port):
        port = int(port)
        return hashlib.sha1("%s" % ((ip,port),)).hexdigest()

    # called by GUI when waiting for invite
    def waitForInvite(self):
        # receive data
        sender, cipher = marshal.loads(AnonNet.recv_once(self.ip, self.port))
        self.DEBUG("Receiving from %s" % sender)

        # parse out sender's ip/port to get corresponding public key
        ip, port = sender.split(':')
        hashkey = self.hash_peer(ip, port)
        pubkey = M2Crypto.RSA.load_pub_key("state/%s.pub" % hashkey)

        # decrypt with public key and retreive data within
        dump = AnonCrypto.decrypt_with_public_rsa(pubkey, cipher)
        (nonce,num_peers,peer_vector) = marshal.loads(dump)
        self.DEBUG("%s, %s, %s" % (nonce, num_peers, peer_vector))

        #send response
        self.accept_phase(ip, port, nonce)

    """
    handles an invite initiated by GUI. prob needs some more robust
    error handling.
    """
    def invite_peer(self, peer):
        """ peer is the string passed in from the GUI """
        parts = peer.split(':')
        ip, port = socket.gethostbyname(parts[0]), int(parts[1])

        # if we have the peer's public key, initiate phase, otherwise warn user
        pubkey = self.hash_peer(ip, port)
        if not os.path.isfile("state/%s.pub" % pubkey):
            self.DEBUG("(%s, %i, %s) has no public key reference, yet" % (ip, port, pubkey))
        else:
            self.DEBUG("(%s, %i, %s) exists!" % (ip, port, pubkey))
            self.invite_phase(ip, port, pubkey)

    """ Phase 1: Send signed (nonce, N, vector(I)) tuple to invitee """
    def invite_phase(self, ip, port, pubkey):
        nonce = 1
        num_peers = 2
        peer_vector = [(self.ip,self.port,self.public_key_string())]

        # package the text up into (nonce, N, [array of peer data])
        text = marshal.dumps((nonce,num_peers,peer_vector))

        # encrypt it
        cipher = AnonCrypto.encrypt_with_private_rsa(self.privKey, text)

        # send to invitee packaged with who it's coming from ((ip:port), signed(text))
        AnonNet.send_to_addr(ip, int(port), marshal.dumps(("%s:%s" % (self.ip,self.port), cipher)))

        """ wait for response back from invitee -- ((ip:port), signed(text)) """
        sender, cipher = marshal.loads(AnonNet.recv_once(self.ip, self.port))
        self.inform_phase(sender, cipher, nonce)

    """ Phase 2: Respond to invite with signed (nonce, ip, port) tuple """
    def accept_phase(self, ip, port, nonce):
        # package and encrypt data
        response = marshal.dumps((nonce,self.ip,self.port))
        cipher = AnonCrypto.encrypt_with_private_rsa(self.privKey, response)

        # respond with ((ip, port), encrypted_data)
        AnonNet.send_to_addr(ip, int(port), marshal.dumps(("%s:%s" % (self.ip, self.port), cipher)))

    """ Phase 3: Inform others (after validating response) """
    def inform_phase(self, sender, cipher, nonce):
        # parse out senders ip/port
        self.DEBUG("Receiving from %s" % sender)
        ip, port = sender.split(':')

        # get corresponding public key
        hashkey = self.hash_peer(ip, port)
        pubkey = M2Crypto.RSA.load_pub_key("state/%s.pub" % hashkey)

        # decrypt and validate!
        dump = AnonCrypto.decrypt_with_public_rsa(pubkey, cipher)
        (recv_nonce,new_ip,new_port) = marshal.loads(dump)
        self.DEBUG("%s, %s, %s" % (recv_nonce, new_ip, new_port))
        if recv_nonce == nonce:
            self.DEBUG("SUCCESSFULLY INVITED/VALIDATED!")

        """ TODO: GOSSIP """

    # send debug notifications to GUI
    def DEBUG(self, msg):
        self.thread.run("<b>Net</b>: " + msg)

    # saves public and private keys to local config directory
    def save_keys(self, rsa_key):
        rsa_key.save_key('config/priv', None)
        rsa_key.save_pub_key('config/pub')

    # loads pubkeys to file
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
