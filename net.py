import os.path
import random
from anon_crypto import AnonCrypto
import M2Crypto.RSA
from M2Crypto import Rand

class Net:
		
	def __init__(self):
		
		# globals
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
			privKey = M2Crypto.RSA.load_key('config/priv')
			pubKey = M2Crypto.RSA.load_pub_key('config/pub')
			
		except:
			# generate new keys
			print "key don't exist/valid"
			Rand.load_file('/dev/urandom', -1)
			newKey = AnonCrypto.random_key(512)
			newKey.save_key('config/priv', None)
			newKey.save_pub_key('config/pub')
			
			# delete existing configuration information
			
			# load keys
			privKey = M2Crypto.RSA.load_key('config/priv')
			pubKey = M2Crypto.RSA.load_pub_key('config/pub')
		
	
	# print public key as string		
	def public_key_string(self):
		return pub_key_to_str(pubKey)
	
	

#def main():
	
#	newNet = Net()
#	newNet.establish_keys()
	
	

#if __name__ == '__main__':
#	main()
	
