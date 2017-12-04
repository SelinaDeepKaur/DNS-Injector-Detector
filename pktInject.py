from optparse import OptionParser

if __name__ == '__main__':
	parser = OptionParser()
	
	parser.add_option("-i", dest="interface",default="eth0")
	parser.add_option("-h", dest="hostsfile")

	(options, args) = parser.parse_args()



