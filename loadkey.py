#!/usr/bin/python

from anon_crypto import AnonCrypto
import M2Crypto.RSA

loadedKey = M2Crypto.RSA.load_key('key')
loadedKey.save_pub_key('keypub2')
