import os.path
import random
import socket
import sys
from anon_crypto import AnonCrypto
import M2Crypto.RSA
from M2Crypto import Rand

from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *

PORT = 20000
SIZEOF_UINT16 = 2

class Net:
    def __init__(self):
        self.privKey = ''
        self.pubKey = ''
        self.establish_keys()
        self.thread = GuiClient()
        print "net object constructed"

    # load / create pub and priv keys in the config folder	
    def establish_keys(self):

        if not os.path.exists('config'):
            os.mkdir('config')

        try:
            # load existing keys
            self.privKey = M2Crypto.RSA.load_key('config/priv')
            self.pubKey = M2Crypto.RSA.load_pub_key('config/pub')

        except:
            # generate new keys
            print "key don't exist/valid"
            Rand.load_file('/dev/urandom', -1)
            newKey = AnonCrypto.random_key(512)
            newKey.save_key('config/priv', None)
            newKey.save_pub_key('config/pub')

            # delete existing configuration information

            # load keys
            self.privKey = M2Crypto.RSA.load_key('config/priv')
            self.pubKey = M2Crypto.RSA.load_pub_key('config/pub')


    # called by GUI right now -- just for testing purposes
    def testMessage(self):
        self.thread.run("testing")

    # print public key as string		
    def public_key_string(self):
        return AnonCrypto.pub_key_to_str(self.pubKey)


    # print private key as string
    def private_key_string(self):
        return AnonCrypto.priv_key_to_str(self.privKey)

    # send invitation
    def send_invitation(self, Host, Port, Pub):

        # resolve host
        Host = gethostbyname(Host)

        # establish socket	
        try:		
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((Host, Port))



        except:
            print "unable to connect to host %s%d" % (Host, Port)

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
        self.socket.connectToHost("localhost", PORT)
        self.sendRequest()

    # send to GUI
    def sendRequest(self):
        self.nextBlockSize = 0
        self.socket.write(self.request)
        self.socket.waitForBytesWritten(1000)
        self.request = None
        self.socket.close()

#def main():

#	newNet = Net()
#	newNet.establish_keys()
#	print newNet.public_key_string()




#if __name__ == '__main__':
#	main()

