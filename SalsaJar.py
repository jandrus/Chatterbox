#!/usr/bin/python2
#
#
# 
'''
	Description:	Houses both client and server modules capable of:
						* x3dh key exchange
						* receiving messages encrypted with Double ratchet protocol
						* send messages encrypted with Double ratchet protocol
	Author:			James L. Andrus Jr.
					jlandrus@protonmail.com
'''	



import os
import hashlib, hmac
import nacl.signing
from nacl.pwhash import argon2id as argon
from nacl.secret import SecretBox
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import URLSafeBase64Encoder as encoder
from nacl.encoding import Base16Encoder as encoder16
from nacl.encoding import RawEncoder
from nacl.bindings import crypto_box_beforenm as sec



#########################
#		  CLIENT		#
#########################
class SalsaJarClient:

	def __init__(self):
		
		self.root_keys = {}
		self.ad_number = {}
		self.used_keys = {}
		self.send_ratc = {}
		self.recv_ratc = {}
		self.sign_key = nacl.signing.SigningKey.generate()
		self.ik_priv, self.ik_pub = gen_DH()
		self.ek_priv, self.ek_pub = gen_DH()
		self.opk_priv, self.opk_pub = gen_DH()
		self.spk_priv = PrivateKey.generate()
		self.spk_pub = self.sign_key.sign(str(self.spk_priv.public_key))


	def close(self, password, filename):
		
		salt = os.urandom(32)
		key = hashlib.pbkdf2_hmac('sha256', password, salt, 1414)
		out_filename = filename + '.LOCK'
		box = SecretBox(key)
		try:
			with open(filename, 'rb') as infile:
				content = infile.read()
			enc_content = box.encrypt(content)
			with open(out_filename, 'wb') as outfile:
				outfile.write(encoder.encode(salt + enc_content))
				outfile.close()
		except Exception as e:
			if hasattr(e, 'message'):
				print e.message()
			else:
				print e


	def open(self, password, filename):
		
		if '.LOCK' == filename[len(filename)-5:]:
			out_filename = filename[:len(filename)-5] + '.UNLOCK'
		else:
			out_filename = filename + '.UNLOCK'
		try:
			with open(filename, 'rb') as infile:
				encoded_content = infile.read()
			decoded_content = encoder.decode(encoded_content)					
			salt = decoded_content[:32]
			key = hashlib.pbkdf2_hmac('sha256', password, salt, 1414)
			box = SecretBox(key)
			dec_content = box.decrypt(decoded_content[32:])
			with open(out_filename, 'wb') as outfile:
				outfile.write(dec_content)
				outfile.close()
		except Exception as e:
			if hasattr(e, 'message'):
				print e.message()
			else:
				print e


	def x3dh_follow(self, user, ik, ek):
		'''
		INPUT
			* user		: user that client is performing x3dh with
			* ik		: identity key of user
			* ek		: Ephemeral key of user
		OUTPUT
			* initial root key between 'user' and client
			* AD number for verification between 'user' and client
		'''
		dh_0 = get_DH_secret(self.spk_priv, PublicKey(ik))
		dh_1 = get_DH_secret(self.ik_priv, PublicKey(ek))
		dh_2 = get_DH_secret(self.spk_priv, PublicKey(ek))
		dh_3 = get_DH_secret(self.used_keys[user], PublicKey(ek))
		# generate root_key and ad number from computed keys
		self.ad_number[user] = gen_ad_number(self.ik_pub, ik)
		self.root_keys[user] = kdf(dh_0 + dh_1 + dh_2 + dh_3)
		# set dh key params
		self.recv_ratc[user] = self.spk_priv


	def x3dh_init(self, user, verify, ik, spk, opk):
		'''
		INPUT
			* user		: user that client is performing x3dh with
			* verify	: key to validate signatures of user
			* ik		: identity key of user
			* spk		: signed pre-key of user
			* opk		: one-time pre-key of user
		OUTPUT
			* initial root key between 'user' and client
			* AD number for verification between 'user' and client
		'''
		if not verify_msg(spk, nacl.signing.VerifyKey(verify)):
			raise Exception('[SalsaJar: X3DH] Signature verification failed')
		else:
			# obtain only key from spk
			spk = spk[64:]
			# generate DH secrets
			dh_0 = get_DH_secret(self.ik_priv, PublicKey(spk))
			dh_1 = get_DH_secret(self.used_keys[user], PublicKey(ik))
			dh_2 = get_DH_secret(self.used_keys[user], PublicKey(spk))
			dh_3 = get_DH_secret(self.used_keys[user], PublicKey(opk))
			# generate root_key and ad number from computed keys
			self.ad_number[user] = gen_ad_number(self.ik_pub, ik)
			self.root_keys[user] = kdf(dh_0 + dh_1 + dh_2 + dh_3)
			# set dh key params
			self.send_ratc[user] = PublicKey(spk)


	def get_follow_params(self, user):
		'''
		INPUT
			* user		: user that client is performing x3dh with
		OUTPUT
			* Saves used keys to dictionary specific to 'user' so that keys can be used again
			* generates new ephemeral keys for new requests
			* Returns keys necessary for x3dh_follow by user 
		'''
		tmp_pub = self.ek_pub
		tmp_priv = self.ek_priv
		self.used_keys[user] = tmp_priv
		self.ek_priv, self.ek_pub = gen_DH()
		return encoder.encode(self.ik_pub + tmp_pub)


	def get_init_params(self, user):
		'''
		INPUT
			* user		: user that client is performing x3dh with
		OUTPUT
			* Saves used keys to dictionary specific to 'user' so that keys can be used again
			* generates new one-time pre-keys for new requests
			* Returns keys necessary for x3dh_init by user 
		'''
		tmp_pub = self.opk_pub
		tmp_priv = self.opk_priv
		self.used_keys[user] = tmp_priv
		self.opk_priv, self.opk_pub = gen_DH()
		return encoder.encode(self.sign_key.verify_key.encode() + self.ik_pub + self.spk_pub + tmp_pub)


	def create_msg(self, user, msg):
		'''
		INPUT
			* user		: user message is being sent to 
			* msg		: unencrypted message being sent
		OUTPUT
			* Encoded(DH_pub key + hmac(MtE) + Encrypted(msg))
		'''
		try:
			self.recv_ratc[user], pub_key = gen_DH()
			dh_sec = get_DH_secret(self.recv_ratc[user], self.send_ratc[user])
			salt = hashlib.md5(dh_sec).digest()
			self.root_keys[user] = kdf(self.root_keys[user], slt=salt)
			box = SecretBox(self.root_keys[user])
			enc_msg = box.encrypt(msg)
			mac = hashlib.pbkdf2_hmac('sha256', msg, self.ad_number[user], 1414)
			return encoder.encode(pub_key + mac + enc_msg)
		except Exception as e:
			print '[SALSAJAR: create_msg] ' + e

	def recv_msg(self, user, packet):
		'''
		INPUT
			* user		: user message is from 
			* packet	: encrypted message received
		OUTPUT
			* Decrypted message with appropriate 
		'''
		try:
			dec_packet = encoder.decode(packet)
			self.send_ratc[user] = PublicKey(dec_packet[:32])
			mac_packet = dec_packet[32:64]
			enc_msg = dec_packet[64:]
			dh_sec = get_DH_secret(self.recv_ratc[user], self.send_ratc[user])
			salt = hashlib.md5(dh_sec).digest()
			self.root_keys[user] = kdf(self.root_keys[user], slt=salt)
			box = SecretBox(self.root_keys[user])
			msg = box.decrypt(enc_msg)
			mac = hashlib.pbkdf2_hmac('sha256', msg, self.ad_number[user], 1414)
			if mac == mac_packet:
				return msg
			else:
				raise Exception('VERIFICATION FAILED: Connection to [' + user + '] aborted.')
		except Exception as e:
			print '[SALSAJAR: recv_msg] ' + str(e)



#########################
#		  SERVER		#
#########################
class SalsaJarServer:

	
	def __init__(self):
		
		self.root_keys = {}
		self.ad_number = {}
		self.used_keys = {}
		self.send_ratc = {}
		self.recv_ratc = {}
		self.sign_key = nacl.signing.SigningKey.generate()
		self.ik_priv, self.ik_pub = gen_DH()
		self.ek_priv, self.ek_pub = gen_DH()
		self.opk_priv, self.opk_pub = gen_DH()
		self.spk_priv = PrivateKey.generate()
		self.spk_pub = self.sign_key.sign(str(self.spk_priv.public_key))


	def close(self, password, filename):
		
		salt = os.urandom(32)
		key = hashlib.pbkdf2_hmac('sha256', password, salt, 1414)
		out_filename = filename + '.LOCK'
		box = SecretBox(key)
		try:
			with open(filename, 'rb') as infile:
				content = infile.read()
			enc_content = box.encrypt(content)
			with open(out_filename, 'wb') as outfile:
				outfile.write(encoder.encode(salt + enc_content))
				outfile.close()
		except Exception as e:
			if hasattr(e, 'message'):
				print e.message()
			else:
				print e


	def open(self, password, filename):
		
		if '.LOCK' == filename[len(filename)-5:]:
			out_filename = filename[:len(filename)-5] + '.UNLOCK'
		else:
			out_filename = filename + '.UNLOCK'
		try:
			with open(filename, 'rb') as infile:
				encoded_content = infile.read()
			decoded_content = encoder.decode(encoded_content)					
			salt = decoded_content[:32]
			key = hashlib.pbkdf2_hmac('sha256', password, salt, 1414)
			box = SecretBox(key)
			dec_content = box.decrypt(decoded_content[32:])
			with open(out_filename, 'wb') as outfile:
				outfile.write(dec_content)
				outfile.close()
		except Exception as e:
			if hasattr(e, 'message'):
				print e.message()
			else:
				print e


	def get_init_params(self, user):
		'''
		INPUT
			* user		: user that server is performing x3dh with
		OUTPUT
			* Saves used keys to dictionary specific to 'user' so that keys can be used again
			* generates new one-time pre-keys for new requests
			* Returns keys necessary for x3dh_init by user 
		'''
		tmp_pub = self.opk_pub
		tmp_priv = self.opk_priv
		self.used_keys[user] = tmp_priv
		self.opk_priv, self.opk_pub = gen_DH()
		return encoder.encode(self.sign_key.verify_key.encode() + self.ik_pub + self.spk_pub + tmp_pub)



	def x3dh_follow(self, user, ik, ek):
		'''
		INPUT
			* user		: user that client is performing x3dh with
			* ik		: identity key of user
			* ek		: Ephemeral key of user
		OUTPUT
			* initial root key between 'user' and client
			* AD number for verification between 'user' and client
		'''
		dh_0 = get_DH_secret(self.spk_priv, PublicKey(ik))
		dh_1 = get_DH_secret(self.ik_priv, PublicKey(ek))
		dh_2 = get_DH_secret(self.spk_priv, PublicKey(ek))
		dh_3 = get_DH_secret(self.used_keys[user], PublicKey(ek))
		# generate root_key and ad number from computed keys
		self.ad_number[user] = gen_ad_number(self.ik_pub, ik)
		self.root_keys[user] = kdf(dh_0 + dh_1 + dh_2 + dh_3)
		# set dh key params
		self.recv_ratc[user] = self.spk_priv


	def create_msg(self, user, msg):
		'''
		INPUT
			* user		: user message is being sent to 
			* msg		: unencrypted message being sent
		OUTPUT
			* Encoded(DH_pub key + hmac(MtE) + Encrypted(msg))
		'''
		self.recv_ratc[user], pub_key = gen_DH()
		dh_sec = get_DH_secret(self.recv_ratc[user], self.send_ratc[user])
		salt = hashlib.md5(dh_sec).digest()
		self.root_keys[user] = kdf(self.root_keys[user], slt=salt)
		box = SecretBox(self.root_keys[user])
		enc_msg = box.encrypt(msg)
		mac = hashlib.pbkdf2_hmac('sha256', msg, self.ad_number[user], 1414)
		return encoder.encode(pub_key + mac + enc_msg)


	def recv_msg(self, user, packet):
		'''
		INPUT
			* user		: user message is from 
			* packet	: encrypted message received
		OUTPUT
			* Decrypted message with appropriate 
		'''
		dec_packet = encoder.decode(packet)
		self.send_ratc[user] = PublicKey(dec_packet[:32])
		mac_packet = dec_packet[32:64]
		enc_msg = dec_packet[64:]
		dh_sec = get_DH_secret(self.recv_ratc[user], self.send_ratc[user])
		salt = hashlib.md5(dh_sec).digest()
		self.root_keys[user] = kdf(self.root_keys[user], slt=salt)
		box = SecretBox(self.root_keys[user])
		msg = box.decrypt(enc_msg)
		mac = hashlib.pbkdf2_hmac('sha256', msg, self.ad_number[user], 1414)
		if mac == mac_packet:
			return msg
		else:
			raise Exception('VERIFICATION FAILED: Connection to [' + user + '] aborted.')


	def move_keys(self, old_user, new_user):
		'''
		INPUT
			* old_user 		: existing user in dictionaries
			* new_user		: desired username for entries in databases
		OUTPUT
			* Remapped entries from old_user to new_user
		'''
		self.root_keys[new_user] = self.root_keys[old_user]
		self.ad_number[new_user] = self.ad_number[old_user]
		self.used_keys[new_user] = self.used_keys[old_user]
		self.send_ratc[new_user] = self.send_ratc[old_user]
		self.recv_ratc[new_user] = self.recv_ratc[old_user]
		del self.root_keys[old_user]
		del self.ad_number[old_user]
		del self.used_keys[old_user]
		del self.send_ratc[old_user]
		del self.recv_ratc[old_user]


def kdf(key, slt='0'*16):
	'''
	INPUT
		* key
		* slt
	OUTPUT
		* key of length 
	'''
#	MIN
	return argon.kdf(SecretBox.KEY_SIZE, key, slt, opslimit=argon.OPSLIMIT_MIN, memlimit=argon.MEMLIMIT_MIN)
#	MODERATE
#	return argon.kdf(SecretBox.KEY_SIZE, key, slt, opslimit=argon.OPSLIMIT_MODERATE, memlimit=argon.MEMLIMIT_MODERATE)
#	SENSITIVE
#	return argon.kdf(SecretBox.KEY_SIZE, key, slt, opslimit=argon.OPSLIMIT_SENSITIVE, memlimit=argon.MEMLIMIT_SENSITIVE)
#	INTERACTIVE
#	return argon.kdf(SecretBox.KEY_SIZE, key, slt, opslimit=argon.OPSLIMIT_INTERACTIVE, memlimit=argon.MEMLIMIT_INTERACTIVE)


def get_DH_secret(private_key, public_key):
	if not isinstance(private_key, PrivateKey) or not isinstance(public_key, PublicKey):
		raise Exception("[SalsaJar: get_DH_secret] Keys must be of type (private, public) respectively")
	return sec(public_key.encode(encoder=RawEncoder),private_key.encode(encoder=RawEncoder),)


def gen_ad_number(ik_1, ik_2):
	'''
	INPUT
		* ik_1	: DH Identity Key 1 (RAW String)
		* ik_2	: DH Identity Key 2 (RAW String)
	OUTPUT
		* md5 hash of the sum of the base 16 representation of the two public DH keys used as salt in HMAC
		  NOTE: The output hash is independent of the order of inputs => both parties should have the same AD number
	'''
	num1 = int(encoder16.encode(ik_1), 16)
	num2 = int(encoder16.encode(ik_2), 16)
	return hashlib.md5(str(num1+num2)).digest()

def gen_DH():
	'''
	INPUT
		* None
	OUTPUT
		* Private and Public DH keys
	'''
	priv_key = PrivateKey.generate()
	pub_key = str(priv_key.public_key)
	return priv_key, pub_key


def verify_msg(signed_msg, verification):
	'''
	INPUT
		* Signed message 
		* Verification key
	OUTPUT
		* Boolean if verification is successful
	'''
	try:
		verification.verify(signed_msg)
		return True
	except:
		return False

