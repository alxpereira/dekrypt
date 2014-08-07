##
# Dekrypt, a lightweight dictionary password cracker for dummies. 
#
# @author : Alexandre Pereira
# @version : 0.0.1
# @licence : WTFPL (Do What the Fuck You Want to Public License) 2004
##

import crypt
import hashlib

##
# bcolors class - contains some color styles for the output messages rendering.

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

##
# output - rendering the messages for the app
# @def output(successType, msg)
# @param successType The type of the message (0 : normal, 1: success, 2: fail)
# @param msg String containing the message to display

def output(successType, msg):
	if(successType == 0):
		out = "[*] " + msg
	elif(successType == 1):
		out = bcolors.OKGREEN + "[+] "+ msg + bcolors.ENDC
	elif(successType == 2):
		out = bcolors.FAIL + "[-] "+ msg + bcolors.ENDC
	return out

##
# un_crypt - decryption process with crypt
# @def un_crypt(cryptPass, word)
# @param cryptPass The crypted pass to decode.
# @param word The dictionnary word to compare.

def un_crypt(cryptPass, word):
	salt = cryptPass[0:2]
	cryptWord = crypt.crypt(word, salt)
	if(cryptWord == cryptPass):
		return word
	return False

##
# un_hashl - decryption process with hashlib
# @def un_hashl(cryptPass, word)
# @param cryptPass The crypted pass to decode.
# @param word The dictionnary word to compare.

def un_hashl(cryptPass, word):
	f = hashlib.md5()
	f.update(word)
	hashWord_md5 = f.hexdigest()
	print hashWord_md5
	print cryptPass
	if(hashWord_md5 == cryptPass):
		print output(1, "Found Type : Looks like a md5 hash...")	
		return word
	u = hashlib.sha1()
	u.update(word)
	hashWord_sha1 = u.hexdigest()
	if(hashWord_sha1 == cryptPass):
		print output(1, "Found Type : Looks like a sha1 hash...")	
		return word
	return False

##
# dekrypt - main dekrypt function, launching the decryption process
# @def dekrypt(cryptPass)
# @param cryptPass The crypted pass to decode.

def dekrypt(cryptPass):
	dictFile = open('dictionnary.txt', 'r')
	for word in dictFile.readlines():
		word = word.strip('\n')
		if(un_crypt(cryptPass, word) != False):
			print output(1, "Found Password : " + word +"\n")
			return
		elif(un_hashl(cryptPass, word) != False):
			print output(1, "Found Password : " + word +"\n")
			return
	print output(2, "Password Not Found.\n")
	return			

##
# main - main initializer
# @def main()

def main():
	passFile = open('password.txt', 'r')
	for line in passFile.readlines():
		if ":" in line:
			user = line.split(':')[0]
			cryptPass = line.split(':')[1].strip(' ').strip('\n')
			print output(0, "Cracking Password "+ cryptPass + " for User " + user)
			dekrypt(cryptPass)
		else:
			cryptPass = line.strip(' ')
			print output(0, "Cracking Password "+ cryptPass)
			dekrypt(cryptPass)

if __name__ == "__main__":
	main()