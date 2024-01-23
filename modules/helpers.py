from sys import exit
from netifaces import interfaces, ifaddresses, AF_INET

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

def pasta(cmd):
    print('\n[================== RUN ON TARGET ==================]\n')
    print(cmd)
    print('\n[================ END RUN ON TARGET ================]\n')