#! Coded by Godlik

import sys, requests, json, time, hashlib
from bs4 import BeautifulSoup as bs


def hbased():
	banner = """	 
 ---=[ hbased.py Tool Coded by @Godlik ]=--- 			 
 			 """
	usage = """ Usage:

 <> [--h] [Help]
 <> [--host] <HOST> [--R] (Robots.txt) [--F] <SAVE.TXT>
 		    [--geturl] [--F] <SAVE.TXT>
 		    [--XSS] <GET/POST> [--L] <WORDLIST.TXT>
<>  [--hash] <MD5|SHA1|SHA512> <HASH> [--L] <WORDLIST.TXT>
		   """	
	try:
		if len(sys.argv) == 0:
			print(banner + usage)
			exit()
			
		if len(sys.argv) >= 1:
			print(banner)
			if sys.argv[1] == '--h' or sys.argv[1] == '--H' or sys.argv[1] == '--help':			
				print(usage)
				sys.exit()
				exit()
			
			if sys.argv[1] == '--hash':
				_thash_ = sys.argv[2]
				_hash_ = sys.argv[3]
				if sys.argv[4] == '--L':
					wordlist = sys.argv[5]
					hashcracker(_thash_, _hash_, wordlist)

			if sys.argv[1] == '--host':
				host = sys.argv[2]
				file = ''
				wordlist = ''
				_wordlist_ = False
				_file_ = False
				
				if sys.argv[3] == '--source':
					sitesource(host)

				if sys.argv[3] == '--R':
					if len(sys.argv) > 4:
						if sys.argv[4] == '--F':
							file = sys.argv[5]
							_file_ = True

					robots(host, file, _file_)
					exit()

				elif sys.argv[3] == '--geturl':
					if len(sys.argv) > 4:
						if sys.argv[4] == '--F':
							file = sys.argv[5]
							_file_ = True

					geturl(host, file, _file_)
					exit()

				elif sys.argv[3] == '--XSS':
					method = sys.argv[4]
					if len(sys.argv) > 5:
						if sys.argv[5] == '--L':
							wordlist = sys.argv[6]
							_wordlist_ = True

					xsscanner(host, method, wordlist, _wordlist_)
					exit()

				elif sys.argv[3] == '--findadm':
					if len(sys.argv) > 4:
						if sys.argv[4] == '--F':
							file = sys.argv[5]
							_file_ = True

					findadm(host, file, _file_)
	except IndexError:
		print(usage)


def hashcracker(_tshash_, _hash_, wordlist):
	print("Processing wordlist...")
	wordlist = open(wordlist, 'r').readlines()
	print("\n------=[Hash %s]=------\n" % (_tshash_))
	for passw in wordlist:
		passw = passw.encode('utf-8')
		if _tshash_ == 'md5':
			__hash = hashlib.md5(passw.strip()).hexdigest()
			passw = passw.decode('ascii').strip()
		elif _tshash_ == 'sha1':
			__hash = hashlib.sha1(passw.strip()).hexdigest()
			passw = passw.decode('ascii').strip()
		elif _tshash_ == 'sha512':
			__hash = hashlib.sha512(passw.strip()).hexdigest()
			passw = passw.decode('ascii').strip()
		if _hash_ == __hash:
			print("\nHash Cracked: %s" % (str(passw)))
			print("------=[Hash %s]=------" % (_tshash_))
			exit()
		else:
			print("Tested: %s <Hash> %s" % (passw, __hash))

def sitesource(host):
	time_ = time.strftime("%H:%M:%S")
	print("\n [*] Start Scanning [%s]: %s\n" % (time_, host))
	print(" Getting Source ...")
	if host[:4] != "http":
		host = "http://" + host
	sauce = requests.get(host).text
	print("\n ------=[Robots.txt]=------\n\n%s\n\n ------=[Robots.txt]=------" % (sauce))


def robots(host, file, _file_):
	try:
        
		if host[:4] != "http":
			host = "http://" + host
		url = host + "/robots.txt"
		time_ = time.strftime("%H:%M:%S")
		print("\n [*] Start Scanning [%s]: %s\n" % (time_, host))
		print(" Getting Robots.txt ... ")
		robot = requests.get(url)
		if robot.status_code == 200:
			print("\n ------=[Robots.txt]=------")
			robot = robot.text
			print("\n" + robot + "\n")
			print(" ------=[Robots End]=------")
			if _file_ == True:
				with open(file, 'a') as f:
					f.write("\n ------=[Robots.txt]=------\n\n" + robot + "\n ------=[Robots.txt]=------")
					f.close()
		else:
			print(" [!] Operation Failed, URL is not online")
	
	except Exception as e:
		print(" [!] Exception Encurred: %s" % (e))
		sys.exit()

def geturl(host, file, _file_):
	try:
		time_ = time.strftime("%H:%M:%S")
		print("\n [*] Start Scanning [%s]: %s\n" % (time_, host))
		print(" Getting Urls ...")
		if host[:4] != "http":
			host = "http://" + host
		sauce = requests.get(host).text
		soup = bs(sauce, 'lxml')
		if _file_ == True:
				with open(file, 'a') as f:
					f.write("\n ------=[Urls]=------\n")
					f.close()
		print("\n ------=[Urls]=------\n")
		for url in soup.find_all('a'):
			_url_ = url.get("href")
			print("--=[ %s" % (_url_))
			if _file_ == True:
				with open(file, 'a') as f:
					f.write("\n--=[ %s" %(_url_))
					f.close()
		print("\n ------=[Urls]=------")
		if _file_ == True:
				with open(file, 'a') as f:
					f.write("\n ------=[Urls]=------")
					f.close()
	except Exception as e:
		print(" [!] Exception Encurred: %s" % (e))
		sys.exit()

def xsscanner(host, method, wordlist, _wordlist_):
	try:
		if host[:4] != "http":
			host = "http://" + host
		time_ = time.strftime("%H:%M:%S")
		print("\n [*] Start Scanning [%s]: %s\n" % (time_, host))
		header = { 'User-Agent' : 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)' }
		print(" Processing [%s] Request.." % (method))
		_payload_ = False
		if _wordlist_ == True:
			try: 
				print(" Testing Payloads...")
				wordlist = open(wordlist, 'r')#.readlines()
				for payload in wordlist:
					if method == 'get' or method == 'GET':
						if payload in requests.get(host + payload, headers=header).text:
							print("\n ------=[Xss]=------\nGot XSS with: %s%s\n ------=[Xss]=------" % (host, payload))
							exit()			
					elif method == 'post' or method == 'POST':
						if payload in requests.post(host + payload, headers=header).text:
							print("\n ------=[Xss]=------\n\nGot XSS with: %s%s\n ------=[Xss]=------" % (host, payload))
							wordlist.close()
							exit()
				print("\n [ ! ] XSS not Found")
				sys.exit()

			except:
				pass
	except:
		pass

def findadm(host, file, _file_):
	if host[:4] != "http":
		host = "http://" + host
	list_ = ["/admin", "/adm", "/administrador", "/administrator", "/admin/login.php", "/admin_login",
			 "/cgi-local/", "/sys/admin/", "/cpanel", "/adm/login.php", "/cgi/admin/", "/login.php",
			 "/login", "/user", "/admincontrol/login.php", "/administratorlogin.php", "/adm/index.php",
			 "/home.php", "/user.html",
			 "/login.html", "/administrator/", "/admin/", "/webadmin/", "/adminarea/", "/admin/account.php",
			 "/admin/index.php", "/siteadmin/login.php", "/siteadmin/index.php", "/admin/index.html",
			 "/admin/login.html", "/admin/account.html", "/admin/login.html", "/admin/admin.html",
			 "/admin/home.php", "/adminpanel.html", "/webadmin.html", "/admin_login.php", "/account.php",
			 "/adminpanel.php", "/user.html",
			 "/user.php", "/adm.html", "/adm/index.html", "/admincontrol/login.html", "/home.php",
			 "/admin.php", "/admin2.php", "/adm/index.php", "/affiliate.php", "/adm.php",
			 "/memberadmin.php", "/administratorlogin.php", "/adminLogin.php",
			 "/panel-administracion/index.php", "/usuarios/login.php", "/admin2.php", "/admin2/login.php",
			 "/admin2/index.php", "/panel-administracion/", "/bb-admin/", "/usuarios/",
			 "/usuario/", "/admin1/", "/admin2/", "/siteadmin/login.html", "/siteadmin/login.php",
			 "/siteadmin/index.php", "/admin/account.php", "/admin/account.html",
             ]
	try:
		time_ = time.strftime("%H:%M:%S")
		print("\n [*] Start Scanning [%s]: %s\n" % (time_, host))
		print("\n ------=[Panel Admin]=------\n")
		for page in list_:
			url_ = host + page
			r = requests.get(url_)
			if r.status_code == 200:
				time_ = time.strftime("%H:%M:%S")
				print ("\n [+] Page Found [%s] > %s > %s\n" % (time_, url_, page))
				if _file_ == True:
					with open(file, 'a') as f:
						f.write("\n[ Found ] %s" %(url_))
						f.close()
			else:
				time_ = time.strftime("%H:%M:%S")
				print(" [-] Page not Found [%s] > %s > %s" % (time_, url_, page))
		print("\n ------=[Panel Admin]=------")
		
	except requests.exceptions.ConnectionError:
		print("[!] Scan Interrupt, the Requests get Blocked!")
		sys.exit()

if __name__ == '__main__':
	hbased()  
