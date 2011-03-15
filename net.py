import os.path
import random
import socket
from anon_crypto import AnonCrypto
import M2Crypto.RSA
from M2Crypto import Rand

class Net:
		
	def __init__(self):
		self.privKey = ''
		self.pubKey = ''
		self.establish_keys()
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
	
	
	

#def main():
	
#	newNet = Net()
#	newNet.establish_keys()
#	print newNet.public_key_string()
	
	
	

#if __name__ == '__main__':
#	main()
	
