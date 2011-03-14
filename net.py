import os.path
from anon_crypto import AnonCrypto
import M2Crypto.RSA

class Net:
	
	def __init__(self):
		self.privKey = ''
		self.pubKey = ''
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
			newKey = AnonCrypto.random_key(512)
			newKey.save_key('config/priv', None)
			newKey.save_pub_key('config/pub')
			
			# delete existing configuration information
			
			# load keys
			privKey = M2Crypto.RSA.load_key('config/priv')
			pubKey = M2Crypto.RSA.load_pub_key('config/pub')

#def main():
	
#	newNet = Net()
#	newNet.establish_keys()
	
	

#if __name__ == '__main__':
#	main()
	
