from optparse import OptionParser

if __name__ == '__main__':
	expression = None
	parser = OptionParser()
	parser.set_conflict_handler("resolve")
	parser.add_option('-i', dest="interface",default="eth0")
	parser.add_option('-h', dest="hostsfile")

	(options, remainder) = parser.parse_args()
	expression = remainder
	print options.interface
	print options.hostsfile
	if expression:
		print expression[0]



