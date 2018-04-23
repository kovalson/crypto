from math import gcd
from random import randint

TEXT_TO_ENCRYPT = "G"

def coprime( a, b ):
	return gcd( a, b ) == 1

def si_sequence( n ):
	"Generowanie ciągu super-rosnącego"

	sequence = []
	constant = 5
	the_sum = 0

	while n > 0:
		new = randint( the_sum + 1, the_sum + 1 + constant )
		sequence.append( new )
		the_sum = the_sum + new
		n = n - 1;

	return sequence, the_sum

def generate_private_key( n ):
	"Generowanie klucza prywatnego"

	# Klucz wynikowy
	key = []

	# Generowanie ciągu super-rosnącego
	w, the_sum = si_sequence( n )

	# Losowanie liczby q większej od sumy elementów ciągu sequence
	q = randint( the_sum + 1, 2 * the_sum )

	# Losowanie r takiego, że q i r są względnie pierwsze
	r = 0
	for i in range( 2, q - 1 ):
		if coprime( i, q ):
			r = i
			break

	return w, q, r

def generate_public_key( priv_key, q, r ):
	"Generowanie klucza publicznego"

	pub_key = []
	for i in range( 0, len( priv_key ) ):
		pub_key.append( (r * priv_key[ i ]) % q )
	return pub_key

def encrypt( text, pub_key ):
	"Szyfrowanie podanego ciągu"

	# Szyfr wynikowy
	cipher = 0

	# Zamiana ciągu znaków na kod ASCII
	# ascii_bin = "".join( format( ord( x ), "b" ) for x in text )
	ascii_bin = text

	# Szyfrowanie
	for b in range( 0, len( ascii_bin ) ):
		bit = ascii_bin[ b ]
		key_frag = pub_key[ b ]
		
		cipher = cipher + (int( bit ) * key_frag)
		
	return cipher

def run( text ):
	w, q, r = generate_private_key( len( text ) )
	pub_key = generate_public_key( w, q, r )
	return pub_key, encrypt( text, pub_key )