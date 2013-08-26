#!/usr/bin/env python
# OWASP ODZ Muti CMS Scanner 2013
# Author : Mennouchi Islam Azeddine azeddine.mennouchi@owasp.org
# This Tool is published Under the GNU public license (for more information license.txt)
# InfoCollector Class :

import re,urllib2,mechanize,xml.etree.ElementTree
from fingerprint import FingerPrint


class InfoCollector:
	def __init__(self):
		self.fprint = FingerPrint()
	
	def get_admin(self,url):
		""" Brute Force du lien de linterface d'administration """
		f = open("doc/admin.txt")
		cont = f.read()
		list = cont.split("\n")
		for elem in list:
			if (self.fprint.check_if_exist(url+"/"+elem)):
				print "[!] Found this directory "+elem+"\n"
				
	def get_info_passive(self,url,type):
		""" enumeration des templates , plugins et conposants a base de contenue de page """
		if (type == "joomla"):
			content = self.fprint.get_cont(self,url)
			linex1 = re.compile("option,(.*?)/")
			linex2 = re.compile('option=(.*?)(&amp;|&|")')
			linex3 = re.compile('/component/(.*?)/')
			linex4 = re.compile('/templates/(.*?)/')
			dir1 = self.fprint.copy(linex1.findall(content))
			dir2 = self.fprint.copy(linex2.findall(content))
			dir3 = self.fprint.copy(linex3.findall(content))
			dir4 = self.fprint.copy(linex4.findall(content))
			print "[!] Plugins Found From passive detection: \n"
			for elem in dir1:
				print elem
			for elem in dir2:
				print elem
			for elem in dir3:
				print elem
			print "[!] Templates Found from passive detection:\n"
			for elem in dir4:
				print elem
		if (type == "wordpress"):
			content = self.fprint.get_cont(url)
			linex = re.compile("/plugins/(.*?)/")
			linex2 = re.compile("/themes/(.*?)/")
			dir = self.fprint.copy(linex.findall(content))
			dir2 = self.fprint.copy(linex2.findall(content))
			print "[!] Plugins Found From passive detection: \n"
			for elem in dir:
				print elem
			print "[!] Themes Found From passive detection: \n"
			for elem in dir2:
				print elem
			
	def get_info_aggressive(self,url,mode,item):
		""" Enumeration de plugins et theme a base d'un list """
		if (item == "plugins"):
			if (mode == "full"):
				print "[!] Enumerating All installed Plugins in "+url+"\n"
				full = open("doc/plugins_full.txt","r")
				cont = full.read()
				list = cont.split("\n")
				for elem in list:
					#print "Test"
					#print "[!] Testing"+elem
					if (self.fprint.check_if_exist(url+"/wp-content/plugins/"+elem)):
						content = self.fprint.get_cont(url+"/wp-content/plugins/"+elem+"/"+"readme.txt")
						regex = re.compile('Stable tag: (.+)')
						version = regex.findall(content)
						if (len(version)!=0):
							print "[!] Found "+elem+" Version "+version[0]
						else:
							print "[!] Found "+elem+" Version ?"
			if (mode == "top"):
				print "[!] Enumerating Most Downloaded installed Plugins in "+url+"\n"
				top = open("doc/plugins.txt","r")
				cont = top.read()
				list = cont.split("\n")
				for elem in list:
					#print "[x] Testing : "+elem
					if (self.fprint.check_if_exist(url+"/wp-content/plugins/"+elem)):
						content = self.fprint.get_cont(url+"/wp-content/plugins/"+elem+"/"+"readme.txt")
						regex = re.compile('Stable tag: (.+)')
						version = regex.findall(content)
						if (len(version)!=0):
							print "[!] Found "+elem+" Version "+version[0]
						else:
							print "[!] Found "+elem+" Version ?"
		if (item == "themes"):
			if (mode == "full"):
				print "[!] Enumerating All installed Themes in "+url+"\n"
				full = open("doc/themes_full.txt","r")
				cont = full.read()
				list = cont.split("\n")
				for elem in list:
					#print "Test"
					#print "[!] Testing"+elem
					if (self.fprint.check_if_exist(url+"/wp-content/themes/"+elem)):
						print "[!] Found "+elem+" Theme"
			if (mode == "top"):
				print "[!] Enumerating Most Downloaded installed Themes in "+url+"\n"
				top = open("doc/themes.txt","r")
				cont = top.read()
				list = cont.split("\n")
				for elem in list:
					#print "[x] Testing : "+elem
					if (self.fprint.check_if_exist(url+"/wp-content/themes/"+elem)):
						print "[!] Found "+elem+" Theme"