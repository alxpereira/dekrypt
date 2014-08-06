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
# dekrypt - main dekrypt function, launching the decryption process
# @def dekrypt(cryptPass)
# @param cryptPass The crypted pass to decode.

def dekrypt(cryptPass):
	salt = cryptPass[0:2]
	dictFile = open('dictionnary.txt', 'r')
	for word in dictFile.readlines():
		word = word.strip('\n')
		cryptWord = crypt.crypt(word, salt)
		if(cryptWord == cryptPass):
			print bcolors.OKGREEN + "[+] Found Password : "+ word +"\n" + bcolors.ENDC
			return
	print bcolors.FAIL + "[-] Password Not Found. \n" + bcolors.ENDC
	return

##
# main - main initializer
# @def main()

def main():
	passFile = open('password.txt')
	for line in passFile.readlines():
		if ":" in line:
			user = line.split(':')[0]
			cryptPass = line.split(':')[1].strip(' ').strip('\n')
			print "[*] Cracking Password "+ cryptPass +" For User : "+ user
			dekrypt(cryptPass)
		else:
			cryptPass = line.strip(' ')
			dekrypt(cryptPass)

if __name__ == "__main__":
	main()