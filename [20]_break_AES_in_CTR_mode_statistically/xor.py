import sys
import re
import string

replchars = re.compile(r'[\n\r]')
def replchars_to_hex(match):
    return r'\x{0:02x}'.format(ord(match.group()))

def get_uint_value(hex_repr):
	if hex_repr not in printable:
		return int(hex_repr[2:],16)
	else:
		return ord(hex_repr)

printable = string.ascii_letters + string.digits + string.punctuation + ' ' + ' | '
def hex_escape(s):
    return ''.join(hex_escape_array(s))

def hex_escape_array(s):
    return [ c if c in printable else r'\x{0:02x}'.format(ord(c)) for c in s ]

manpage = """ Xor files : python xor.py file1 [ list of files ] """


def xor( string1, string2 ):
	return [ chr(c1 ^ c2) for (c1, c2) in zip(string1, string2)]


if __name__ == '__main__':

	if len(sys.argv) < 3:
		print(manpage)
		
	else:
		for i in filter(lambda o: sys.argv[1] != sys.argv[o], range(2, len(sys.argv))):
			print("\n " + sys.argv[1] +" ^ " + sys.argv[i] + " \n")
			print( hex_escape("".join(xor(open(sys.argv[1], "rb").read(), open(sys.argv[i], "rb").read()))))
			print("\n---\n")
