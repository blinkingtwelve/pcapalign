#(c) 2014 Wicher Minnaard <wicher@nontrivialpursuit.org>
#License: GPL-3 (http://opensource.org/licenses/GPL-3.0)

import pcap #https://pypi.python.org/pypi/pylibpcap/0.6.3
from collections import namedtuple, OrderedDict
from binascii import hexlify
import struct


#base filter, select unfragmented ICMP/UDP/TCP IP traffic
bfilter4 = '(ip[6:2] & 0x1fff = 0) and (proto 1 or proto 6 or proto 17)' #unfragmented icmp/tcp/udp
bfilter6 = '((ip6[6] = 58) or (ip6[6] = 6) or (ip6[6] = 17))' #unfragmented with nonextended header, icmpv6/tcp/udp
bfilter = '(%s or %s)' % (bfilter4,bfilter6)

pcinfo = namedtuple('pclass', 'proto src dst dport')

class pclass(object):
	#for IP over Ethernet

	def __init__(self,etherb):
		self.ver = ord(etherb[14]) >> 4
		assert self.ver in (4,6), "Does not look like IPv{4,6}..."
		parser = self.parse4 if self.ver == 4 else self.parse6
		self.info = pcinfo(**parser(etherb[14:]))
		self.proto, self.src, self.dst, self.dport = self.info
		self.thedict = None
		self.thefilter = None

	def __str__(self):
		return '{proto}:{dport} {src}->{dst}'.format(**self.asdict())

	def __repr__(self):
		return self.__str__()

	def __hash__(self):
		return(hash(self.info))

	def __eq__(self,other):
		return self.info == other.info

	def parse4(self,b):
		d = {}
		hlen = ord(b[0]) & 0x0f
		d['proto'] = ord(b[9])
		d['src']   = b[12:16]
		d['dst']   = b[16:20]
		ds = (hlen * 4) #start of payload
		if d['proto'] in (6,17):  #only for tcp/udp
			d['dport'] = b[ds+2:ds+4]
		else:
			d['dport'] = b[ds:ds+1] #not really a 'port' but the icmp type
		return d

	def parse6(self,b):
		d = {}
		d['proto'] = ord(b[6])
		d['src']   = b[8:24]
		d['dst']   = b[24:40]
		# payload starts at octet 40 since we filter for ipv6 with non-extended headers
		if d['proto'] in (6,17):  #only for tcp/udp
			d['dport'] = b[42:44]
		else:
			d['dport'] = b[40] #not really a 'port' but the icmp type
		return d

	def asdict(self):
		if self.thedict: return self.thedict #cached
		pp = {1:'icmp', 6:'tcp', 17:'udp', 58:'icmp6'}
		def btoa4(b):
			return pcap.ntoa(struct.unpack('i',b)[0])
		def btoa6(b):
			return ':'.join([hexlify(b[x:x+2]) for x in range(0,15,2)])
		finfo = OrderedDict()
		btoa = btoa4 if self.ver == 4 else btoa6
		finfo['src'] = btoa(self.src)
		finfo['dst'] = btoa(self.dst)
		finfo['proto'] = pp[self.proto]
		if self.proto in (6,17):
			finfo['dport'] = struct.unpack('!H',self.dport)[0]
		else:
			finfo['dport'] = ord(self.dport)
		self.thedict = finfo
		return finfo

	def tofilter(self):
		if self.thefilter: return self.thefilter #cached
		d = self.asdict()
		pf =  'src host {src} and dst host {dst} '.format(**d)
		pf += 'and proto {:d} '.format(self.proto)
		if self.proto in (6,17):
			pf += 'and dst port {dport}'.format(**d)
		else:
			if self.ver == 4:
				pf += 'and {proto}[0] = {dport}'.format(**d)
			else: # libpcap: 'IPv6 upper-layer protocol is not supported by proto[x]'
				pf += 'and ip6[40] = {dport}'.format(**d)
		self.thefilter = pf = '(%s)' % pf
		return pf



def packeter(pcapfile, pfilter=None):
	#BUG: pylibpcap leaks file descriptors
	p = pcap.pcapObject()
	p.open_offline(pcapfile)
	if pfilter: p.setfilter(pfilter,0,0)
	while True:
		pk = p.next()
		if pk:
			yield pk
		else:
			break


def isether(pcapfile):
	p = pcap.pcapObject()
	p.open_offline(pcapfile)
	return (p.datalink() == 1)

