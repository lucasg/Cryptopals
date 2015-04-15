import xor
import sys 
import collections

manpage = """ matrix of Xor files : python matrix.py [ list of files ] """


get_array = lambda m,i: [ m[j][i] for j in range(0, len(m)) if i < len(m[j]) ] 
get_printable = lambda array: filter(lambda c: c in xor.printable, array)
get_printable_with_zero = lambda array: filter(lambda c: 0 != ord(c) or c in xor.printable, array)
most_common_image = lambda m: [ collections.Counter(get_printable(get_array(m,i))).most_common(1) if len([x for x in get_printable(get_array(m,i))]) < 3/4.0*len([x for x in get_printable_with_zero(get_array(m,i))]) else (' ',0) for i in range(clen) ]



if __name__ == '__main__':


	if not len(sys.argv):
		print(manpage)

	else:
		m = []
		for i in range(2, len(sys.argv)):
			x = xor.xor(open(sys.argv[1], "rb").read(), open(sys.argv[i], "rb").read())
			m.append(x)

			# print (xor.hex_escape(','.join(x)))

		clen = len(open(sys.argv[1], "rb").read())
		# "Most Frequent for " + sys.argv[1] + " : "  + 
		print(''.join( t[0][0] if t != [] else '?' for t in most_common_image(m) ))
