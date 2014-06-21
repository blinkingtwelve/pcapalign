#!/usr/bin/env python2
#(c) 2014 Wicher Minnaard <wicher@nontrivialpursuit.org>
#License: GPL-3 (http://opensource.org/licenses/GPL-3.0)

import argparse,sys,bisect
import fcntl,termios,struct
import libalign as la
import packetstuff as ps
from collections import namedtuple
from itertools import groupby
from time import sleep
from prettytable import PrettyTable #https://pypi.python.org/pypi/PrettyTable/0.7.2

try:
	from prettytable import PrettyTable
except ImportError:
	exit('You need the "prettytable" module; https://pypi.python.org/pypi/PrettyTable/0.7.2')
try:
	import pcap
except ImportError:
	exit('You need the "pylibpcap" module; https://pypi.python.org/pypi/pylibpcap/0.6.3')


global opts
askew_t = namedtuple('skew', 'skew, scount, pcount, tspan')

class askew(askew_t):
	# average of skews
	def plusstreak(self, streak):
		scount = self.scount + 1
		pcount = self.pcount + streak.pcount
		tspan = self.tspan + streak.tspan
		skew = ((self.pcount*self.skew) + (streak.pcount*streak.skew)) / pcount
		return askew(skew,scount,pcount,tspan)


def getgeo():
	#stolen from http://stackoverflow.com/questions/566746/how-to-get-console-window-width-in-python
	#py3.3 has os.get_terminal_size() ;-)
	h, w, hp, wp = struct.unpack('HHHH',
	fcntl.ioctl(sys.stdout.fileno(),
	termios.TIOCGWINSZ,
	struct.pack('HHHH', 0, 0, 0, 0)))
	return (w, h)


def run():
	global opts
	if not (ps.isether(opts.pcap1) and ps.isether(opts.pcap2)):
		exit('Error: Non-ethernet encapsulation type in input files.')
	lefilter = ps.bfilter
	if opts.pcapfilter: lefilter = ps.bfilter + ' and (' + opts.pcapfilter + ')'
	pclasses = la.getpkclassolap(opts.pcap1,opts.pcap2,pfilter=lefilter,minmatch=opts.minmatch)
	if not pclasses: exit('Cannot find any traffic common in A and B')
	total = len(pclasses)
	for no,((pkclass, cnt), summ) in enumerate(skews(pclasses),1):
		if not opts.quiet: draw(no,total,pkclass,cnt,summ)
		if no == opts.limit: break


def skewcollapse(streaks):
	global opts
	def streak2astreak(s):
		a_s = dict(**s.info.__dict__)
		a_s['scount'] = 1
		return askew(**a_s)
	summ = []
	cur_askew = streak2astreak(streaks[0])
	for s in streaks[1:]:
		if s.skew < cur_askew.skew+1**-opts.bucketround:
			cur_askew = cur_askew.plusstreak(s)
		else:
			summ.append(cur_askew)
			cur_askew = streak2astreak(s)
	summ.append(cur_askew)
	return summ


def skews(pclasses):
	global opts
	lestreaks = []
	for (pkclass,cnt) in pclasses:
		pfilter = '%s and %s' % (ps.bfilter,pkclass.tofilter())
		if opts.pcapfilter:
			pfilter = '%s and %s' % (opts.pcapfilter, pfilter)
		newstreaks = la.getskew(opts.pcap1, opts.pcap2, pfilter=pfilter, decimals=opts.round)
		newstreaks = filter(lambda a: a.tspan > opts.span, newstreaks)
		if not newstreaks:continue
		for sk in newstreaks:
			bisect.insort(lestreaks, sk)
		summ = skewcollapse(lestreaks)
		summ.sort(key=lambda a: a.skew, reverse=False)
		summ.sort(key=lambda a: a.scount, reverse=True)
		yield ((pkclass, cnt), summ)


def draw(no,total,pkclass,cnt,summ):
	global opts
	done = '%%0%dd/%d' % (len(str(total)), total) % no # m%a%g%i%c%!
	cinfo = '{proto:>5s}:{dport:<5}'
	if len(pkclass.dst) == 4: #ipv4
		cinfo+= ' {src:15s}->{dst:15s}\n'
	else: #ipv6
		cinfo+= ' {src}\n         -> {dst}'
	cinfo = cinfo.format(**pkclass.asdict())

	bucketsize = '0.'+ ((opts.bucketround-1) * '0') + '1s' if opts.bucketround else '1.0s'
	output = ('%s buckets, %s classes, last (%d pkts):\n%s\n' % (bucketsize, done, cnt, cinfo))
	t = PrettyTable(['SKEW (AVG)','#STREAKS','#PACKETS','TOTAL TIMESPAN'])
	t.float_format = ' .6'
	t.align = 'r'
	linesleft = getgeo()[1] - 10
	if linesleft < 1: linesleft = 1
	for skinfo in summ[:linesleft]:
		t.add_row(skinfo)
	clear = b"\x1b[2J\x1b[H"
	output = '%s%s%s' % (clear, output, t.get_string())
	print(output)
	if opts.slomo: sleep(0.2)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='Calculates time skew of pcap(ng) file B relative to pcap(ng) file A using traffic correlation. A and B should have some traffic in common. NAT spoils the fun. Supports IPv6.')
	alargs = parser.add_argument_group(title='Algorithm parameters')
	alargs.add_argument('-r', '--round', metavar="NUMBER", type=int, default=3, help="Round fractions of seconds in packet timestamps to NUMBER of decimals. 3 (round to nearest millisecond) is the default, it is usually a good choice for situations with sub-millisecond jitter between capture point A and B.")
	alargs.add_argument('-l', '--limit', metavar="NUMBER", type=int, default=500, help="Use max NUMBER of autogenerated filters (default 500).")
	alargs.add_argument('-s', '--span', metavar="SECONDS", type=float, default=0.01, help="Disregard streaks which span < SECONDS (default 0.01).")
	alargs.add_argument('-m', '--minmatch', metavar="NUMBER", type=int, default=5, help="Only consider classes which match more than NUMBER packets in both A and B. Default 5.")
	dispargs = parser.add_argument_group(title='Display parameters')
	dispargs.add_argument('-q', '--quiet', action="store_true", help="Suppress table output.")
	dispargs.add_argument('--slomo', action="store_true", help="Wait for one jiffie between skew table display updates.")
	dispargs.add_argument('-b', '--bucketround', metavar="NUMBER", type=int, default=1, help="Size of skew buckets, 10**-NUMBER. Default 1 for 0.1s buckets.")
	parser.add_argument('-f', '--pcapfilter', metavar='FILTER', help="Use pcap filter expression FILTER to limit examined traffic ('man 7 pcap-filter').")
	parser.add_argument('pcap1', metavar="PCAP_A")
	parser.add_argument('pcap2', metavar="PCAP_B")
	global opts
	opts = parser.parse_args()

	try:
		run()
	except KeyboardInterrupt:
		exit('Interrupted')

