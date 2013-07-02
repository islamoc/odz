#!/usr/bin/python
from fingerprint import FingerPrint
from infocollector import InfoCollector
from tester import Tester
from generate_list import SvnParser
from online_search import OnlineSearch
import getopt
import sys


def help():
	print "Multi CMS Scanner Version 1.0\n"
	print "usage : python scannerc.py -u (url) [options]\n"
	print "OPTIONS LIST : \n"
	print "-u --url= specifier le lien de site a scanner"
	print "-t (type) --type= specifier le type de CMS (wordpress,joomla)"
	print "-e (mode) --enumerate enumerer les plugins (just pour wordpress) mode : full(la liste complete) / top(liste des plugins les plus telecharges)"
	print "-m (mode) --theme enumerer les themes (just pour wordpress) mode : full(la liste complete) / top(liste des themess les plus telecharges)"
	print "-v --vuln enumerer les plugins vulnerables"
	print "-c --vulnt enumerer les themes vulnerables"
	print "-h --help afficher ce message d'aide"

help()

try:
	opts, args = getopt.getopt(sys.argv[1:], "hu:t:e:m:vc",["help","url=","type=","enumerate=","theme=","vuln","vulnt"])
except getopt.GetoptError as err:
	print(err)
	help()
	sys.exit(2)
fp = FingerPrint()
ic = InfoCollector()
ts = Tester()
os = OnlineSearch()
svn = SvnParser()
for o,u in opts:
	if o in ("-h","--help"):
		help()
	elif o in ("-u","--url"):
		url = fp.adrstrip(u)
		t = fp.detect_cms(url)
		print "[!] CMS installed is : "+t
		if (t == "wordpress"):
			print "[x] Searching for plugins or themes in the code (passive search): \n"
			ic.get_info_passive(url,t)
			print "[x] Fingerprinting using readme.html \n"
			print "[!] Wordpress Version is : "+fp.wp_fp_rm(url)+"\n"
			print "[x] Fingerprinting Using advanced fingerprinting \n"
			print "[!] Wordpress Version is :"+str(fp.wp_fp(url))+"\n"
			print "[x] Searching for plugins and Themes using agressive mode: \n"
			ic.get_info_aggressive(url,"top","plugins")
			print "\n"
			ic.get_info_aggressive(url,"top","themes")
			print "\n"
			print "[x] Scanning for core Vulns : \n"
			ts.wp_vulns(fp.wp_fp(url))
			print "\n"
			print "[x] Scanning for plugins Vulns :\n"
			ts.wp_plugins_vulns(url)
			print "\n"
			print "[x] Scanning for Themes Vulns :\n"
			ts.wp_theme_vulns(url)
	elif o in ("-t","--type"):
		type = u
		if (type == "wordpress"):
			print "[x] Searching for plugins or themes in the code (passive search): \n"
			ic.get_info_passive(url,type)
			print "[x] Fingerprinting using readme.html \n"
			print "[!] Wordpress Version is : "+fp.wp_fp_rm(url)+"\n"
			print "[x] Fingerprinting Using advanced fingerprinting \n"
			print "[!] Wordpress Version is :"+fp.wp_fp(url)+"\n"
			print "[x] Searching for plugins and Themes using agressive mode: \n"
			ic.get_info_aggressive(url,"top","plugins")
			print "\n"
			ic.get_info_aggressive(url,"top","themes")
			print "\n"
			print "[x] Scanning for core Vulns : \n"
			ts.wp_vulns(fp.wp_fp(url))
			print "\n"
			print "[x] Scanning for plugins Vulns :\n"
			ts.wp_plugins_vulns(url)
			print "\n"
			print "[x] Scanning for Themes Vulns :\n"
			ts.wp_theme_vulns(url)
		#if (type == "joomla"):
			#TODO
	elif o in ("-e","--enumerate"):
		mode = u
		print mode
		print fp.detect_cms(url)
		if ((fp.detect_cms(url) == "wordpress") or (type == "wordpress")):
			ic.get_info_aggressive(url,mode,"plugins")
		else :
			print "[!] enumeration not availaible for joomla"
	elif o in ("-m","--theme"):
		mode = u
		if ((fp.detect_cms(url) == "wordpress") or (type == "wordpress")):
			ic.get_info_aggressive(url,mode,"themes")
		else :
			print "[!] enumeration not availaible for joomla"
	elif o in ("-v","--vuln"):
		if ((fp.detect_cms(url) == "wordpress") or (type == "wordpress")):
			ts.wp_plugins_vulns(url)
		else :
			print "[!] enumeration not availaible for joomla"
	elif o in ("-c","--vulnt"):
		if ((fp.detect_cms(url) == "wordpress") or (type == "wordpress")):
			ts.wp_theme_vulns(url)
		else :
			print "[!] enumeration not availaible for joomla"
		