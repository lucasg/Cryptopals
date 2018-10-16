# -*- coding: utf-8 -*-
import collections
import string
import sys
import os

# A list of easily printable char
printable = string.ascii_letters + string.digits + string.punctuation + ' ' + ' | '

def xor( string1, string2 ):
	'''
		Xor two string
	'''
	return [ chr(c1 ^ c2) for (c1, c2) in zip(string1, string2)]

def hex_parse(hex_repr):
	'''
		Get back the unsigned integer value from a string which could be :
		 - either a single char
		 - a hex represention in the format r'\\x{0:02x}'
	'''
	if hex_repr not in printable:
		return int(hex_repr[2:],16)
	else:
		return ord(hex_repr)

def hex_escape(c):
	'''
		Escape the non-easily printable characters in the format : \\xHH.
	'''
	return c if c in printable else r'\x{0:02x}'.format(ord(c))

def hex_escape_array(s):
	'''
		Escape the non-easily printable characters in the format : \\xHH in an array.
	'''
	return [ hex_escape(c) for c in s ]
    
def get_most_likely_keys(ciphertexts, min_clen):
	'''
		Retrieve the most likely keys.
		For now it returns the five most frequents char.
	'''
	
	# transposition
	ctext_mat_t = [[0 for y in range(len(ciphertexts))] for x in range(min_clen)] 
	for i in range(min_clen):
		for j in range(len(ciphertexts)):
			ctext_mat_t[i][j] = ciphertexts[j][i]



	keys = [[ chr(ord(' ') ^ ord(x[0])) for x in collections.Counter(ctext_mat_t[i]).most_common(5)] for i in  range(min_clen)]

	# padding for the longest ciphertext
	for k in range(min_clen, max(map(len, ciphertexts))):
		keys.append([chr(0)])

	return keys

def get_ciphertexts(folder_path):
	'''
		Load ciphertexts and compute the most likely key.
	'''
	
	list_files = [f for f in filter(lambda fd: os.path.isfile(os.path.join(folder_path, fd)), os.listdir(folder_path))]
	print(list_files, len(list_files))
	ciphertexts = [[] for f in range(len(list_files))]

	for f in list_files:
		
		filename = os.path.join(folder_path, f)
		with open( filename , "rb") as c:
			ctext = c.read()
			print(int(f), ':', len(ctext))
			ciphertexts[int(f) - 1] = [chr(x) for x in ctext]

	min_clen = min(map(len, ciphertexts))
	print(min_clen)
	print("test")
	for c in ciphertexts:
		print(len(c))

	keys = get_most_likely_keys(ciphertexts, min_clen)

	return ciphertexts, keys
