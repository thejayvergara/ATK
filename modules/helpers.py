from sys import exit
from netifaces import interfaces, ifaddresses, AF_INET
from hashlib import md5

def populateChoices(entrymsg, choiceList):
    while True:
        print(entrymsg)
        i = 1
        tempList = []
        for item in choiceList:
            print('      ' + str(i) + ') ' + item)
            i += 1
        print('[?] CHOICE: ', end='')

        try:
            choice = input()
        except KeyboardInterrupt:
            exit(0)

        if choice == '':
            continue
        elif int(choice) <= len(choiceList):
            choice = choiceList[int(choice)-1]
            return choice
        else:
            print('[!] Invalid choice. Try again.')
            input('[?] Press any key to continue ...')

def whichIP():
    ipList = []
    for interface in interfaces():
        ipv4 = ifaddresses(interface)
        if AF_INET in ipv4.keys():
            ipList.append(ipv4[AF_INET][0]['addr'])
    while True:
        print('[?] What IP address to listen on: ')
        i = 1
        for ip in ipList:
            print('      ' + str(i) + ') ' + ip)
            i += 1
        print('[?] CHOICE: ', end='')
        try:
            choice = input()
        except KeyboardInterrupt:
            exit(0)

        if choice == '':
            continue
        elif int(choice) <= len(ipList):
            return ipList[int(choice)-1]
        else:
            print('[!] Invalid choice. Try again.')
            input('[?] Press any key to continue ...')

def targetPasta(cmd):
    print('\n[================== RUN ON TARGET ==================]\n')
    print(cmd)
    print('\n[================ END RUN ON TARGET ================]\n')

def pwnPasta(cmd):
    print('\n[================== RUN ON PWNBOX ==================]\n')
    print(cmd)
    print('\n[================ END RUN ON PWNBOX ================]\n')

def verifyHash(relFilePath):
    print(f'[+] Generating MD5 checksum for {relFilePath}')
    originalMD5 = md5(open(relFilePath, 'rb').read()).hexdigest()
    while True:
        try:
            print('[?] Paste target MD5 checksum output here to compare: ', end='')
            remoteMD5 = input()
            if remoteMD5 == '':
                continue
            elif originalMD5 == remoteMD5:
                print('[+] MD5 checksum matches. You\'re good to go!')
                break
            else:
                print('[-] Uh-oh.. MD5 checksum doesn\'t match. Try file transfer again.')
                break
        except KeyboardInterrupt:
            exit(0)
