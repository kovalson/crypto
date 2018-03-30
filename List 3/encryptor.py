'''
	Krzysztof Tatarynowicz
	221497

	Kryptografia
	Lista 2
'''

import binascii
import os
import jks
import sys
import OpenSSL
import base64
import hashlib
from random import randint
from Crypto import Random
from Crypto.Util import Counter
from Crypto.Cipher import AES

KEYSTORE_PASSWORD_FILE	= "config"
BLOCK_SIZE = 16

def short_mode( mode ):
	if mode == "cbc":
		return AES.MODE_CBC

def jks_password( jks_file, passphrase, key_alias, key_password = None ):
	ASN1 = OpenSSL.crypto.FILETYPE_ASN1
	keystore = jks.KeyStore.load( jks_file, passphrase )
	pk_entry = keystore.private_keys[ key_alias ]

	if not pk_entry.is_decrypted():
		pk_entry.decrypt( key_password )

	pkey = OpenSSL.crypto.load_privatekey( ASN1, pk_entry.pkey )
	public_cert = OpenSSL.crypto.load_certificate( ASN1, pk_entry.cert_chain[ 0 ][ 1 ] )
	trusted_certs = [ OpenSSL.crypto.load_certificate( ASN1, cert.cert ) for alias, cert in keystore.certs ]
	ctx = OpenSSL.SSL.Context( OpenSSL.SSL.TLSv1_METHOD )
	ctx.use_privatekey( pkey )
	ctx.use_certificate( public_cert )
	ctx.check_privatekey()
	cert_store = ctx.get_cert_store()
	for cert in trusted_certs:
		cert_store.add_cert( cert )
	return ctx

def load_keystore_password():
	with open( KEYSTORE_PASSWORD_FILE, "r" ) as fo:
		password = fo.read()
	return str( password )

def int_of_string( s ):
	return int( binascii.hexlify( iv ), 16 )

def pad( s ):
	return s + b"\0" * (AES.block_size - len( s ) % AES.block_size)

def encrypt( message, key, mode = AES.MODE_CBC, key_size = 256 ):
	message = pad( message )
	iv = Random.new().read( AES.block_size )
	cipher = AES.new( key, mode, iv )
	return iv + cipher.encrypt( message )

def decrypt( ciphertext, key, mode = AES.MODE_CBC ):
	iv = ciphertext[ :AES.block_size ]
	cipher = AES.new( key, mode, iv )
	plaintext = cipher.decrypt( ciphertext[ AES.block_size: ] )
	return plaintext.rstrip( b"\0" )

def encrypt_file( file_name, key, mode = AES.MODE_CBC ):
	with open( file_name, "rb" ) as fo:
		plaintext = fo.read()
	enc = encrypt( plaintext, key, mode )
	with open( file_name + ".encrypted", "wb" ) as fo:
		fo.write( enc )

def decrypt_file( file_name, key, mode = AES.MODE_CBC ):
	with open( file_name, "rb" ) as fo:
		ciphertext = fo.read()
	dec = decrypt( ciphertext, key, mode )
	with open( file_name + ".decrypted", "wb" ) as fo:
		fo.write( dec )

def encrypt_file_chall( file_name, key, mode = AES.MODE_CBC ):
	with open( file_name, "rb" ) as fo:
		plaintext = fo.read()

	# get random message from plaintext and encrypt it
	msgs = plaintext.split()
	if len( msgs ) == 1:
		plaintext = msgs[ 0 ][ randint( 0, len( msgs[ 0 ] - 1 ) ) ]
	else:
		plaintext = msgs[ randint( 0, len( msgs ) - 1 ) ]

	enc = encrypt( plaintext, key, mode )

	with open( file_name + ".encrypted", "wb" ) as fo:
		fo.write( enc )

key = b"\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18"

def main():
	arguments = sys.argv

	if len( arguments ) < 5:
		print( "Usage: python ./encryptor.py enc_mode prog_mode op file_name" )
		print( "enc_mode: CBC, etc..." )
		print( "prog_mode: oracle, challenge" )
		print( "op: encrypt, decrypt" )
		return

	enc_mode = sys.argv[ 1 ]
	prog_mode = sys.argv[ 2 ]
	op = sys.argv[ 3 ]
	file_name = sys.argv[ 4 ]

	if prog_mode == "oracle":
		if op == "encrypt":
			encrypt_file( file_name, key, short_mode( enc_mode ) )
		elif op == "decrypt":
			decrypt_file( file_name, key, short_mode( enc_mode ) )
	elif prog_mode == "challenge":
		if op == "encrypt":
			encrypt_file_chall( file_name, key, short_mode( enc_mode ) )
		elif op == "decrypt":
			decrypt_file( file_name, key, short_mode( enc_mode ) )

main()

# encrypt_file( "to_enc.txt", key )
# decrypt_file( "to_enc.txt.enc", key )