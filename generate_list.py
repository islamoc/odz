#!/usr/bin/env python

# OWASP ODZ Muti CMS Scanner 2013
# Author : Mennouchi Islam Azeddine azeddine.mennouchi@owasp.org
# This Tool is published Under the GNU public license (for more information license.txt)
# SvnParser Class :

class SvnParser:
	"""Cette classe est pour la mise a jour des bdd des failles """

	def get_dirs(type):
		""" maj des theme et plugins wordpress a partir d un repertoire svn """
		if type == "theme":
			print "[!] Generating Themes list ..."
			linex = re.compile('<li><a href=".+">(.+)/</a></li>')
			request = mechanize.Request("http://themes.svn.wordpress.org/")
			response1 = mechanize.urlopen(request)
			res = response1.read()
			dir = linex.findall(res)
			print dir
		if type == "plugin":
			print "[!] Generating Plugins list ..."
			linex = re.compile('<li><a href=".+">(.+)/</a></li>')
			request = mechanize.Request("http://plugins.svn.wordpress.org/")
			response1 = mechanize.urlopen(request)
			res = response1.read()
			dir = linex.findall(res)
			print dir
	def get_joom():
		""" maj de la bdd des faille pour joomla """
		request = mechanize.Request("http://web-center.si/joomscan/joomscandb.php")
		response = mechanize.urlopen(request)
		res = response.read()