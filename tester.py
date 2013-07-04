#!/usr/bin/env python

# OWASP ODZ Muti CMS Scanner 2013
# Author : Mennouchi Islam Azeddine azeddine.mennouchi@owasp.org
# This Tool is published Under the GNU public license (for more information license.txt)
# Tester Class :

import re,urllib2,mechanize,md5,xml.etree.ElementTree,sha
from fingerprint import FingerPrint
from distutils.version import StrictVersion

class Tester:
	""" La classe des tests de vulnirabilites """
	def __init__(self):
		self.fprint = FingerPrint()
		
	def wp_vulns(self,version):
		""" detection Vuln. dans le corps de WP """
		tree = xml.etree.ElementTree.parse("doc/wp_vulns.xml")
		p = tree.findall("wordpress")
		#print p
		#p2 = tree.findall("hash/file")
		for ele in p:
			vrs = ele.attrib["version"]
			#print vrs
			if (vrs == version):
				s = ele.getchildren()
				for elem in s:
					r = elem.getchildren()
					#print "test"
					print "Title : "+r[0].text
					print "Reference : "+r[1].text
					print "Type : "+r[2].text
	def wp_plugins_vulns(self,url):
		"""detection des vuln. dans les plugins"""
		tree = xml.etree.ElementTree.parse("doc/plugin_vulns.xml")
		p = tree.findall("plugin")
		#cmp = lambda x, y: StrictVersion(x).__cmp__(y)
		vregex = re.compile("[\d.]*\d+")
		found = 0
		for ele in p:
			dir = ele.attrib["name"]
			if (self.fprint.check_if_exist(url+"/wp-content/plugins/"+dir)):
				rdm = self.fprint.get_cont(url+"/wp-content/plugins/"+dir+"/readme.txt")
				regex = re.compile('Stable tag: ([\d.]*\d+)')
				iversion1 = self.fprint.copy(regex.findall(rdm))
				#print iversion1
				try :
					iversion = iversion1[0]
				except IndexError :
					iversion = "?"
				#print iversion
				s = ele.getchildren()
				for elem in s :
					r = elem.getchildren()
					version = self.fprint.copy(vregex.findall(r[0].text))
					#print version
					try :
						v = version[0]
					except IndexError :
						v = "?"
					#print v
					if (len(r) == 3):
						#found = 1
						print "[!] Title : "+r[0].text
						print "[!] Ref. : "+r[1].text
						print "[!] Type : "+r[2].text
					if (len(r) == 4):
						print "[!] Title : "+r[0].text
						print "[!] Ref.1 : "+r[1].text
						print "[!] Ref.2 : "+r[2].text
						print "[!] Type : "+r[3].text
					if ( (v == "?") or (iversion == "?")):
						print "[x] You need to check we could not detect the version"
					else:
						#print StrictVersion(v).__cmp__(iversion)
						if ((StrictVersion(v).__cmp__(iversion) == 0) or (StrictVersion(iversion).__cmp__(v) == -1)):
							print "[x] Your CMS is infected with this vuln."
							found = 1
						else :
							print "[x] Your CMS is Safe From this vuln."
		if (found == 0):
			print "[!] No Vuln. Plugin was found !"
	
	def wp_theme_vulns(self,url):
		"""detection des vuln. dans les themes"""
		tree = xml.etree.ElementTree.parse("doc/theme_vulns.xml")
		p = tree.findall("theme")
		found = 0
		for ele in p:
			dir = ele.attrib["name"]
			if (self.fprint.check_if_exist(url+"/wp-content/themes/"+dir)):
				found = 1
				s = ele.getchildren()
				for elem in s:
					r = elem.getchildren()
					print "[!] Title : "+r[0].text
					print "[!] Ref. : "+r[1].text
					print "[!] Type : "+r[2].text
		if (found == 0):
			print "[!] No Vlun. Theme Was Found "
