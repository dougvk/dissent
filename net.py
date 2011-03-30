from __future__ import with_statement

import os.path
import random
import socket
import sys
import hashlib
import marshal
import SocketServer
import threading

from anon_crypto import AnonCrypto
from anon_net import AnonNet
from utils import Utilities

import M2Crypto.RSA

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *


class Net(QThread):
    def __init__(self, parent):
        QThread.__init__(self)
        self.nodes = []
        self.privKey = ''
        self.pubKey = ''

        #load up your priv/pub keypair
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

        self.server = SimpleServer((self.ip, self.port), self.handler_factory())
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()
        self.DEBUG(str(self.ip) + ":" + str(self.port))
    
    def run(self):
        pass

    def recv_invite(self, data):
        # receive data
        msg, key = marshal.loads(data)

        # get (nonce, num_peers, peer_vector from msg) to verify msg
        (nonce, num_peers, peer_vector) = marshal.loads(msg)

        # parse out sender's ip/port to get saved pubkey, then verify
        ip, port = peer_vector[0][0], peer_vector[0][1]
        hashkey = self.hash_peer(ip, port)
        pubkey = M2Crypto.RSA.load_pub_key("state/%s.pub" % hashkey)
        verified = AnonCrypto.verify_with_key(pubkey, data)

        self.DEBUG("INVITE: %s, %s, %s, %s" % (nonce, num_peers, peer_vector, verified))
        for peer in peer_vector:
            self.add_peer(peer[0], peer[1])

        """ NOTE: should probably emit a signal to update peers """
        self.DEBUG("update peers")

        #send response
        if verified: self.accept_phase(ip, port, nonce)

    """ Phase 2: Respond to invite with signed (nonce, ip, port) tuple """
    def accept_phase(self, ip, port, nonce):
        # package and encrypt data
        response = marshal.dumps((nonce,self.ip,self.port))
        cipher = AnonCrypto.sign_with_key(self.privKey, response)

        # respond with ((ip, port), encrypted_data)
        AnonNet.send_to_addr(ip, int(port), marshal.dumps(("accept", cipher)))

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
        invite = marshal.dumps((nonce,num_peers,peer_vector))

        # sign it
        cipher = AnonCrypto.sign_with_key(self.privKey, invite)

        # send to invitee packaged with who it's coming from ((ip:port), signed(text))
        AnonNet.send_to_addr(ip, int(port), marshal.dumps(("invite", cipher)))

    """ Phase 3: Inform others (after validating response) """
    def inform_phase(self, data):
        msg, key = marshal.loads(data)

        # get corresponding public key to verify
        (recv_nonce, new_ip, new_port) = marshal.loads(msg)
        hashkey = self.hash_peer(new_ip, new_port)
        pubkey = M2Crypto.RSA.load_pub_key("state/%s.pub" % hashkey)
        verified = AnonCrypto.verify_with_key(pubkey, data)

        # decrypt and validate!
        self.DEBUG("INFORMING: %s, %s, %s, %s" % (recv_nonce, new_ip, new_port, verified))
        if verified:
            self.DEBUG("SUCCESSFULLY INVITED/VALIDATED!")
            self.add_peer(new_ip, new_port)
            self.DEBUG("update peers")

        """ Broadcast to all peers """
        voucher = marshal.dumps((self.ip, self.port, new_ip, new_port, self.peer_public_key_string(new_ip, new_port)))
        sig_voucher = AnonCrypto.sign_with_key(self.privKey, voucher)
        self.save_voucher(new_ip, new_port, sig_voucher)
        self.broadcast_to_all_peers(marshal.dumps(("inform", sig_voucher)))

    def recv_voucher(self, data):
        msg, key = marshal.loads(data)

        # get corresponding public key to verify
        (vouch_ip, vouch_port, new_ip, new_port, pub_key_string) = marshal.loads(msg)
        hashkey = self.hash_peer(vouch_ip, vouch_port)
        pubkey = M2Crypto.RSA.load_pub_key("state/%s.pub" % hashkey)
        verified = AnonCrypto.verify_with_key(pubkey, data)

        self.DEBUG("VOUCHER: %s, %s, %s, %s, %s" % (vouch_ip, vouch_port, new_ip, new_port, pub_key_string))
        if verified:
            self.DEBUG("SUCCESSFULLY VOUCHED")
            self.save_voucher(new_ip, new_port, data)
            self.save_peer_key(new_ip, new_port, pub_key_string)

    def save_voucher(self, ip, port, voucher):
        hashkey = self.hash_peer(ip, port)
        f = open("state/%s.voucher" % hashkey, 'w')
        f.write(voucher)
        f.close()

    def save_peer_key(self, ip, port, pub_key_string):
        hashkey = self.hash_peer(ip, port)
        Utilities.write_str_to_file("state/%s.pub" % hashkey, pub_key_string)

    def broadcast_to_all_peers(self, voucher):
        for node in self.nodes:
            ip, port = node[0], node[1]
            AnonNet.send_to_addr(ip, port, voucher)

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
                    continue
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

    # send debug notifications to GUI
    def DEBUG(self, msg):
        self.emit(SIGNAL("messageReceived(QString)"), QString(msg))

    def add_peer(self, ip, port):
        peer_f = open('state/peers.txt','a')
        debug_f = open('state/debug.txt','a')
        hashkey = self.hash_peer(ip, port)
        peer_f.write("\n%s %s" % (socket.gethostbyaddr(ip)[0], port))
        debug_f.write("\n%s %s" % (socket.gethostbyaddr(ip)[0], hashkey))
        self.nodes.append((ip,int(port),hashkey))

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
        
    # return peer public key as string
    def peer_public_key_string(self, ip, port):
        hashkey = self.hash_peer(ip, port)
        key = M2Crypto.RSA.load_pub_key("state/%s.pub" % hashkey)
        return AnonCrypto.pub_key_to_str(key)

    # return a TCPHandler with the GUI callback function
    def handler_factory(self):
        def create_handler(*args, **keys):
            return SingleTCPHandler(self, *args, **keys)
        return create_handler

class SingleTCPHandler(SocketServer.BaseRequestHandler):
    """ One instance per connection. """
    def __init__(self, parent, *args, **keys):
        self.parent = parent
        SocketServer.BaseRequestHandler.__init__(self, *args, **keys)

    def handle(self):
        data = AnonNet.recv_from_socket(self.request)
        (function, msg) = marshal.loads(data)
        if function == "invite":
            self.parent.recv_invite(msg)
        elif function == "accept":
            self.parent.inform_phase(msg)
        elif function == "inform":
            self.parent.recv_voucher(msg)
        else:
            self.parent.emit(SIGNAL("messageReceived(QString)"), QString("not sure what to do with: " + str(function)))

class SimpleServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass):
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)
