#!/usr/bin/python

from anon_crypto import AnonCrypto
import M2Crypto.RSA

print "starting crypto test"
newKey = AnonCrypto.random_key(512)
newKey.save_key('key', None)
newKey.save_pub_key('keypub')
