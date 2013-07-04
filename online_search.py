#!/usr/bin/env python

# OWASP ODZ Muti CMS Scanner 2013
# Author : Mennouchi Islam Azeddine azeddine.mennouchi@owasp.org
# This Tool is published Under the GNU public license (for more information license.txt)
# OnlineSearch Class :

import re,urllib2,mechanize,xml.etree.ElementTree
from fingerprint import FingerPrint


class OnlineSearch:
	""" la classe de recherche enligne des failles """
	def __init__(self):
		self.fprint = FingerPrint()
	
	def site_search(self,com):
		"""recherche des informatation sur les composants sur packetstorm.org"""
		sere = self.fprint.get_cont("http://packetstormsecurity.org/search/files/?q="+com+"&s=files")
		if (re.search(r"No Results Found",sere)):
			print "No Results Found in packetstormsecurity.org"
		else:
			linex1 = re.compile(r'<a class="ico text-plain" href="(.+)" title="Size: (.+) KB">(.*?)</a>')
			dir1 = self.fprint.copy(linex1.findall(sere))
			for elem in dir1:
				print "Link : packetstormsecurity.org"+elem[0]
				print "Size : "+elem[1]+" KB"
				print "Title : "+elem[2]
				print "\n"
				print "---------------------------------------------------------"