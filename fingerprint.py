#!/usr/bin/env python

# OWASP ODZ Muti CMS Scanner 2013
# Author : Mennouchi Islam Azeddine azeddine.mennouchi@owasp.org
# This Tool is published Under the GNU public license (for more information license.txt)
# FingerPrint Class :
import re,urllib2,mechanize,md5,xml.etree.ElementTree

class FingerPrint:


	def __init__(self):
		self.fp = 1
	
	def detect_cms(self,url):
		if (self.check_if_exist(url+"/templates/")):
			return "joomla"
		if (self.check_if_exist(url+"/wp-content/")):
			return "wordpress"
		else :
			return "unknown"
	
	def adrstrip(self,url):
		url = url.replace("http://","")
		url = url.replace("https://","")
		url = "http://"+url
		if (url[len(url)-1] == "/"):
			url = url[:(len(url)-1)]
		return url

	def exist(self,list,a):
		""" verifier si un element existe dans une list """
		i = 0
		for elem in list:
			if (elem == a):
				i=i+1
		if (i>0):
			return True
		else:
			return False

	def copy(self,list):
		"""Generer une list qui contient pas un element plus d'une fois"""
		new = []
		i = 0
		while i<len(list):
			if (self.exist(new,list[i]) == False):
				new.append(list[i])
			i=i+1
		return new
			

	def check_if_exist(self,url):
		"""verefier si un chemin ou un fichier existe dans le serveur"""
		""" verefier si un lien existe """
		request = mechanize.Request(url)
		BAD_REQ = [400,401,404]
		try :
			response = mechanize.urlopen(request)
			if response.code in BAD_REQ:
				return False
			else:
				return True
		except urllib2.HTTPError, error:
			if error.code in BAD_REQ:
				return False
			else:
				return True

	def get_cont(self,url):
		"""recuperer le contenue d'une page ou un fichier dans le serveur"""
		request = mechanize.Request(url)
		try:
			response = mechanize.urlopen(request)
			res = response.read()
			return res
		except urllib2.HTTPError, error:
			res = error.read()
			return res

	def joomla_fp(self,url):
		""" Joomla Fingerprinting detection de version de joomla """
		res = self.get_cont(url)
		res2 = self.get_cont(url+"/index.php?option=com_esi")
		rdm = self.get_cont(url+"/README.txt")
		htaccess = self.get_cont(url+"/htaccess.txt")
		dist = self.get_cont(url+"/configuration.php-dist")
		if ((re.search(r"<\/html> <!-- \d{1,30} -->",res)) or (self.check_if_exist(url+"/administrator/templates/joomla_admin/images/security.png")) or (self.check_if_exist(url+"/language/english.xml")) or re.search(r"The page you are trying to access does not exist",res2)):
			print "[!] Version 1.0.x \n"
		if ((re.search(r" Joomla! 1.5 - Open Source Content Management",res)) or (self.check_if_exist(url+"/administrator/templates/khepri/images/j_login_lock.jpg")) or (self.check_if_exist(url+"/administrator/templates/khepri/images/j_button1_next.png")) or (re.search(r"404- Component not found",res2))) :
			print "[!] Version 1.5.x \n"
		if ((re.search(r" package to version 3.0.x",rdm)) or (self.check_if_exist(url+"administrator/templates/isis/img/glyphicons-halflings.png"))) :
			print "[!] Version 3.0.x \n"
		if ((re.search(r"47 2005-09-15 02:55:27Z rhuk",htaccess))) :
			print "[!] htaccess.txt revealed [1.0.0 - 1.0.2]\n"
		if ((re.search(r"423 2005-10-09 18:23:50Z stingrey",htaccess))) :
			print "[!] htaccess.txt revealed 1.0.3\n"
		if ((re.search(r"1005 2005-11-13 17:33:59Z stingrey",htaccess))) :
			print "[!] htaccess.txt revealed [1.0.4 - 1.0.5]\n"
		if ((re.search(r"1570 2005-12-29 05:53:33Z eddieajau",htaccess))) :
			print "[!] htaccess.txt revealed [1.0.6 - 1.0.7]\n"
		if ((re.search(r"2368 2006-02-14 17:40:02Z stingrey",htaccess))) :
			print "[!] htaccess.txt revealed [1.0.8 - 1.0.9]\n"
		if ((re.search(r"4085 2006-06-21 16:03:54Z stingrey",htaccess))) :
			print "[!] htaccess.txt revealed 1.0.10\n"
		if ((re.search(r"4756 2006-08-25 16:07:11Z stingrey",htaccess))) :
			print "[!] htaccess.txt revealed 1.0.11\n"
		if ((re.search(r"5973 2006-12-11 01:26:33Z robs",htaccess))) :
			print "[!] htaccess.txt revealed 1.0.12\n"
		if ((re.search(r"5975 2006-12-11 01:26:33Z robs",htaccess))) :
			print "[!] htaccess.txt revealed [1.0.13 - 1.0.15]\n"
		if ((re.search(r"47 2005-09-15 02:55:27Z rhuk",dist))) :
			print "[!] configuration.php-dist revealed 1.0.0\n"
		if ((re.search(r"217 2005-09-21 15:15:58Z stingrey",dist))) :
			print "[!] configuration.php-dist revealed [1.0.1 - 1.0.2]\n"
		if ((re.search(r"506 2005-10-13 05:49:24Z stingrey",dist))) :
			print "[!] configuration.php-dist revealed [1.0.3 - 1.0.7]\n"
		if ((re.search(r"2622 2006-02-26 04:16:09Z stingrey",dist))) :
			print "[!] configuration.php-dist revealed 1.0.8\n"
		if ((re.search(r"3754 2006-05-31 12:08:37Z stingrey",dist))) :
			print "[!] configuration.php-dist revealed [1.0.9 - 1.0.10]\n"

						
	def wp_fp(self,url):
		""" WP Fingerprinting detection de version de WP """
		tree = xml.etree.ElementTree.parse("doc/wp_versions.xml")
		p = tree.findall("file")
		#p2 = tree.findall("file/hash")
		#p3 = tree.findall("file/hash/version")
		for elem in p:
			s = elem.getchildren()
			src = elem.attrib["src"]
			content = self.get_cont(url+"/"+src)
			md5p = md5.new(content).hexdigest()
			#print src
			for ele in s:
				md5c = ele.attrib["md5"]
				#print "[!] comparing "+md5c+" hash for "+src+" : "+md5p
				if (md5c == md5p):
					r = ele.getchildren()
					return r[0].text
			#print md5
	def wp_fp_rm(self,url):
		""" WP fingerprinting detection de version de WP """
		content = self.get_cont(url+"/readme.html")
		regex = re.compile(r'Version (.+)')
		res = self.copy(regex.findall(content))
		return res[0]
