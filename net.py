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

KEY_LENGTH = 1024
DEFAULT_PORT = 9000

class Net(QThread):
    def __init__(self, parent):
        QThread.__init__(self)
        self.nodes = []
        self.privKey = ''
        self.pubKey = ''

        #load up your priv/pub keypair
        self.establish_keys()

        # read in peers from peers file
        self.establish_peers()

        # save ip, port, and hashkey for yourself
        self.ip = self.get_my_ip()
        self.port = self.get_my_port()
        self.hashkey = self.hash_peer(self.ip, self.port)

        # created threaded server
        self.server = ThreadedServer((self.ip, self.port), self.handler_factory())
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.start()
        self.DEBUG(str(self.ip) + ":" + str(self.port))
    
    # need to implement this because Net subclasses QThread
    def run(self):
        pass

    """ GUI initiated user expellation """
    def expel_peer(self, ip, port):
        self.DEBUG("IP/PORT to expel: %s:%s" % (ip, port))

        # create voucher for peers to save
        expel_voucher = marshal.dumps((self.ip, self.port, ip, port, self.peer_public_key_string(ip,port)))
        cipher = AnonCrypto.sign_with_key(self.privKey, expel_voucher)
        self.broadcast_to_all_peers(marshal.dumps(("expel",cipher)))

        # remove from peerlist
        index = self.nodes.index((ip, int(port), self.peer_public_key_string(ip,port)))
        self.nodes.pop(index)
        self.update_peerlist()
        self.DEBUG("Expelled!")

        # save the voucher you sent out
        self.save_voucher(self.ip,self.port,cipher,"expelvoucher")
    
    """ delete expelled peer from list given a proper voucher. save the voucher """
    def recv_expel_voucher(self, data):
        msg, key = marshal.loads(data)
        (vouch_ip, vouch_port, expel_ip, expel_port, expel_pubkey) = marshal.loads(msg)
        self.DEBUG("Recieved a expel voucher from %s:%s against %s:%s" % (vouch_ip, vouch_port, expel_ip, expel_port))

        # verify the expel voucher
        hashkey = self.hash_peer(vouch_ip, vouch_port)
        pubkey = M2Crypto.RSA.load_pub_key("state/%s.pub" % hashkey)
        verified = AnonCrypto.verify_with_key(pubkey, data)

        # if verified, remove and save voucher
        if verified:
            try:
                index = self.nodes.index((expel_ip, int(expel_port), expel_pubkey))
                self.nodes.pop(index)
                self.DEBUG("Expelled!")
                self.update_peerlist()
            except:
                if self.ip == expel_ip and int(self.port) == int(expel_port):
                    self.nodes = []
                    self.update_peerlist()
                    self.DEBUG("I'm being booted :(")
                else:
                    self.DEBUG("Booting someone I don't know")
            self.save_voucher(vouch_ip,vouch_port,data,"expelvoucher")
        else:
            self.DEBUG("Not a valid voucher -- not expelling")

    """ GUI initiated clique dropout """
    def drop_out(self):
        self.DEBUG("Dropping out of the clique")

        # create dropout voucher (IP, PORT, PUBKEY)
        dropout_voucher = marshal.dumps((self.ip, self.port, self.public_key_string()))

        # sign it
        cipher = AnonCrypto.sign_with_key(self.privKey, dropout_voucher)

        # give all peers signed voucher of your voluntary quitting
        self.broadcast_to_all_peers(marshal.dumps(("quit", cipher)))

        # empty peerlist and exit
        self.nodes = []
        self.update_peerlist()

    """ Delete verified peer from list given a proper voucher. Save the voucher. """
    def recv_quit_voucher(self, data):
        msg, key = marshal.loads(data)
        (ip, port, pubkey_string) = marshal.loads(msg)
        self.DEBUG("Recieved a dropout voucher from %s:%s" % (ip, port))

        # verify quit voucher
        hashkey = self.hash_peer(ip, port)
        pubkey = M2Crypto.RSA.load_pub_key("state/%s.pub" % hashkey)
        verified = AnonCrypto.verify_with_key(pubkey, data)
        
        # try to remove if verified, then save voucher
        if verified:
            try:
                index = self.nodes.index((ip, int(port), pubkey_string))
                self.nodes.pop(index)
                self.DEBUG("Verified Peer %s:%s is dropping out! Index: %s" % (ip, port, index))
                self.update_peerlist()
            except:
                self.DEBUG("Verified Peer %s:%s is not on your list!" % (ip, port))
            self.save_voucher(ip,port,data,"dropoutvoucher")
        else:
            self.DEBUG("Peer %s:%s not verified" % (ip, port))

    """
    GUI initiated invite
    """
    def invite_peer(self, ip, port):
        # if we have the peer's public key, initiate phase, otherwise warn user
        pubkey = self.hash_peer(ip, port)
        if not os.path.isfile("state/%s.pub" % pubkey):
            self.DEBUG("(%s, %i, %s) has no public key reference, yet" % (ip, port, pubkey))
        else:
            self.DEBUG("(%s, %i, %s) exists!" % (ip, port, pubkey))
            self.invite_phase(ip, port, pubkey)

    """ Phase 0: receive an invite from a peer """
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

        if verified:
            # save the list of peers sent to you if verified
            self.DEBUG("verified invite contents: %s, %s, %s, %s" % (nonce, num_peers, peer_vector, verified))
            self.save_peer_list(peer_vector)

            # update GUI list
            self.update_peerlist()

            #send response
            self.accept_phase(ip, port, nonce)
        else:
            self.DEBUG("received invite not verifiable!")

    """ Phase 1: Send signed (nonce, N, vector(I)) tuple to invitee """
    def invite_phase(self, ip, port, pubkey):
        # create nonce, # peers, vector containing (ip, port, pubkey) of all peers
        nonce = 1
        num_peers = len(self.nodes) + 1
        peer_vector = [(self.ip,self.port,self.public_key_string())]
        for node in self.nodes:
            hashkey = self.hash_peer(node[0], node[1])
            if hashkey != self.hashkey:
                peer_vector.append(node)

        # package the text up into (nonce, N, [array of peer data])
        invite = marshal.dumps((nonce,num_peers,peer_vector))

        # sign it
        cipher = AnonCrypto.sign_with_key(self.privKey, invite)

        # send to invitee packaged with who it's coming from ((ip:port), signed(text))
        AnonNet.send_to_addr(ip, int(port), marshal.dumps(("invite", cipher)))

    """ Phase 2: Respond to invite with signed (nonce, ip, port) tuple """
    def accept_phase(self, ip, port, nonce):
        # package and encrypt data
        response = marshal.dumps((nonce,self.ip,self.port))
        cipher = AnonCrypto.sign_with_key(self.privKey, response)

        # respond with ((ip, port), encrypted_data)
        AnonNet.send_to_addr(ip, int(port), marshal.dumps(("accept", cipher)))

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

            self.update_peerlist()

        # broadcast to all peers, save voucher
        voucher = marshal.dumps((self.ip, self.port, new_ip, new_port, self.peer_public_key_string(new_ip, new_port)))
        sig_voucher = AnonCrypto.sign_with_key(self.privKey, voucher)
        self.save_voucher(new_ip, new_port, sig_voucher, "voucher")
        self.broadcast_to_all_peers(marshal.dumps(("inform", sig_voucher)))

    """ Phase 4: Someone just invited and vouched for a new peer """
    def recv_voucher(self, data):
        msg, key = marshal.loads(data)

        # get corresponding public key to verify
        (vouch_ip, vouch_port, new_ip, new_port, pub_key_string) = marshal.loads(msg)
        hashkey = self.hash_peer(vouch_ip, vouch_port)
        pubkey = M2Crypto.RSA.load_pub_key("state/%s.pub" % hashkey)
        verified = AnonCrypto.verify_with_key(pubkey, data)

        self.DEBUG("Received voucher from %s:%s for %s:%s" % (vouch_ip, vouch_port, new_ip, new_port))

        # save voucher and add peer to nodelist if vouched properly
        if verified:
            self.DEBUG("SUCCESSFULLY VOUCHED")
            self.save_voucher(new_ip, new_port, data, "voucher")
            self.save_peer_key(new_ip, new_port, pub_key_string)
            self.add_peer(new_ip, new_port)

            self.update_peerlist()
        else:
            self.DEBUG("voucher not verified, no action taken")

    # save a voucher received over the network
    def save_voucher(self, ip, port, voucher, voucher_type):
        hashkey = self.hash_peer(ip, port)
        f = open("state/%s.%s" % (hashkey, voucher_type), 'w')
        f.write(voucher)
        f.close()

    # save the peer list sent during invite phase
    def save_peer_list(self, peer_vector):
        for peer in peer_vector:
            hashkey = self.hash_peer(peer[0], peer[1])
            if hashkey != self.hashkey:
                Utilities.write_str_to_file("state/%s.pub" % hashkey, peer[2])
                self.add_peer(peer[0], peer[1])

    # save a peers pubkey string sent over network
    def save_peer_key(self, ip, port, pub_key_string):
        hashkey = self.hash_peer(ip, port)
        Utilities.write_str_to_file("state/%s.pub" % hashkey, pub_key_string)

    # broadcast message to everyone in peer list
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

        # otherwise, create peers file for later
        if not os.path.exists('state'):
            os.mkdir('state')
        if not os.path.isfile('state/peers.txt'):
            self.DEBUG("creating peers.txt")
            open('state/peers.txt','w').close()

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

    # retrieve port value specified in config/port
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
        with open(filename, 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip, port = socket.gethostbyname(parts[0]), int(parts[1])
                nodes.append((ip,port,self.peer_public_key_string(ip,port)))
        return nodes

    # returns hash of ip:port peer
    def hash_peer(self, ip, port):
        port = int(port)
        return hashlib.sha1("%s" % ((ip,port),)).hexdigest()

    # send debug notifications to GUI
    def DEBUG(self, msg):
        self.emit(SIGNAL("messageReceived(QString)"), QString(msg))

    # add peer to self.nodes -- make sure its not you!
    def add_peer(self, ip, port):
        hashkey = self.hash_peer(ip, port)
        if hashkey != self.hashkey:
            self.nodes.append((ip,int(port),self.peer_public_key_string(ip,port)))

    def update_peerlist(self):
        peer_f = open('state/peers.txt','w')
        for peer in self.nodes:
            hashkey = self.hash_peer(peer[0], peer[1])
            if hashkey != self.hashkey:
                peer_f.write("%s %s\n" % (socket.gethostbyaddr(peer[0])[0], peer[1]))
        self.emit(SIGNAL("updatePeers()"))

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

    # return peer public key as string
    def peer_public_key_string(self, ip, port):
        hashkey = self.hash_peer(ip, port)
        key = M2Crypto.RSA.load_pub_key("state/%s.pub" % hashkey)
        return AnonCrypto.pub_key_to_str(key)

    """ factory to return TCPHandler with a reference to the net instance, """
    """ thus it can emit a signal to GUI and call the appropriate net functions """
    def handler_factory(self):
        def create_handler(*args, **keys):
            return TCPHandler(self, *args, **keys)
        return create_handler

# handler for each TCP connection
class TCPHandler(SocketServer.BaseRequestHandler):
    """ One instance per connection. """
    def __init__(self, parent, *args, **keys):
        self.parent = parent
        SocketServer.BaseRequestHandler.__init__(self, *args, **keys)

    """ send data to correct function in Net class """
    def handle(self):
        data = AnonNet.recv_from_socket(self.request)
        (function, msg) = marshal.loads(data)
        if function == "invite":
            self.parent.recv_invite(msg)
        elif function == "accept":
            self.parent.inform_phase(msg)
        elif function == "inform":
            self.parent.recv_voucher(msg)
        elif function == "quit":
            self.parent.recv_quit_voucher(msg)
        elif function == "expel":
            self.parent.recv_expel_voucher(msg)
        else:
            self.parent.emit(SIGNAL("messageReceived(QString)"), QString("not sure what to do with: " + str(function)))

# threaded server for receiving messages
class ThreadedServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass):
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)
