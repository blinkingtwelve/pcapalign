#(c) 2014 Wicher Minnaard <wicher@nontrivialpursuit.org>
#License: GPL-3 (http://opensource.org/licenses/GPL-3.0)

import math
import numpy
import packetstuff as ps
from collections import Counter, OrderedDict, namedtuple
from difflib import SequenceMatcher, Match
from operator import itemgetter
from functools import total_ordering

sinfo = namedtuple('sinfo', 'skew pcount tspan')

@total_ordering
class streak(object):

	def __init__(self,**kwargs):
		self.info = sinfo(**kwargs)
		self.skew, self.pcount, self.tspan = self.info

	def __str__(self):
		return '%f %d %f' % (self.info)

	def __hash__(self):
		return hash(self.info)

	def __eq__(self,other):
		return self.info == other.info

	def __lt__(self,other):
		return self.skew < other.skew


def timedeltas(seq,decimals=None):
	ts =  numpy.fromiter(seq,numpy.float)
	tsd = ts[1:] - ts[:-1]
	if decimals != None: tsd = numpy.round(tsd, decimals=decimals)
	return (ts, tsd)


def frags(ts1,ts2,decimals=0,minlen=1):
	ts1,tsd1 = timedeltas(ts1,decimals=decimals)
	ts2,tsd2 = timedeltas(ts2,decimals=decimals)
	sm = SequenceMatcher(a=tsd1,b=tsd2, autojunk=True)
	matches = set(filter(lambda a:a.size >= minlen, sm.get_matching_blocks()))
	sm = SequenceMatcher(b=tsd1,a=tsd2, autojunk=True)
	matches.update((Match(m.b,m.a,m.size) for m in sm.get_matching_blocks() if m.size >= minlen))
	
	streaks = [streak(	skew = ts2[m.b] - ts1[m.a],
						pcount = m.size + 1,
						tspan = ts1[m.a+m.size] - ts1[m.a])
					for m in matches]
	return streaks


def getskew(f1,f2,pfilter=None,decimals=None):
	pf1 = map(itemgetter(2), ps.packeter(f1, pfilter=pfilter))
	pf2 = map(itemgetter(2), ps.packeter(f2, pfilter=pfilter))
	return frags(pf1,pf2,decimals=decimals)


def getpkclassolap(f1,f2,pfilter=None,minmatch=5):
	pf1 = map(itemgetter(1), ps.packeter(f1, pfilter=pfilter))
	pf2 = map(itemgetter(1), ps.packeter(f2, pfilter=pfilter))
	return pkolap(pf1,pf2,minmatch=minmatch)


def pkclasses(pkiter,minmatch=5):
	pclasses = (ps.pclass(b) for b in pkiter)
	lecnt = OrderedDict()
	for pc, cnt in Counter(pclasses).most_common():
		# too little packets makes them useless for comparisons
		if cnt > minmatch: lecnt[pc] = cnt
	return lecnt


def pkolap(pkiter1, pkiter2,minmatch=5):
	h1 = pkclasses(pkiter1,minmatch=minmatch)
	h2 = pkclasses(pkiter2,minmatch=minmatch)
	shorter, longer = sorted((h1,h2), key=lambda a: len(a))
	inboth = [pc for pc in shorter.keys() if pc in longer]
	olaps = [(pc,shorter[pc]+longer[pc]) for pc in inboth]
	olaps.sort(key=itemgetter(1), reverse=False) #low counts first
	return olaps
