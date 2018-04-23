from mh import *

def bit_array_to_int( bit_array ):
	out = 0
	for bit in bit_array:
		out = (out << 1) | bit
	return out

def bit_array_to_ascii( bit_array ):
	return chr( bit_array_to_int( bit_array ) )

def attack( pub_key = [7, 14, 11, 5], cipher = 12 ):
	"Atak na Merkle-Hellman Knapsack"

	# Długość klucza
	n = len( pub_key )

	# Tablica "Q":
	# Q[ i ][ j ] = True, gdy istnieje podzbiór b1, b2, ..., bi,
	# który sumuje się do j, 0 <= i <= n, 0 <= j <= cipher
	Q = []
	for i in range( 0, n + 1 ):
		Q.append( [ False ] * (cipher + 1) )
	Q[ 0 ][ 0 ] = True

	# Obliczanie tablicy "Q"
	for i in range( 0, n ):
		for j in range( 0, cipher + 1 ):
			if (j - pub_key[ i ] < 0):
				Q[ i + 1 ][ j ] = Q[ i ][ j ]
			else:
				Q[ i + 1 ][ j ] = Q[ i ][ j - pub_key[ i ] ] or Q[ i ][ j ]

	# Ciąg wyjściowy (odszyfrowany)
	plaintext = [ 0 ] * n

	# Odzyskiwanie informacji z tablicy "Q"
	i = n
	j = cipher
	while i > 0:
		if (j - pub_key[ i - 1 ]) >= 0:
			if Q[ i - 1 ][ j - pub_key[ i - 1 ]] is True:
				plaintext[ i - 1 ] = plaintext[ i - 1 ] + 1
				j = j - pub_key[ i - 1 ]
		i = i - 1

	return "".join( str( x ) for x in plaintext )

def main():
	pub_key, cipher = run( "110000000000000000000000000000000000000000000000000000000000" )
	# return pub_key, cipher
	return attack( pub_key, cipher )

print( main() )