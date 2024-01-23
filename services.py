from subprocess import run, Popen, DEVNULL
from sys import exit
import helpers

httpServers = [
    'Python'
]

def startHTTP():
    entrymsg = '[?] Which HTTP server to use:'
    choice = helpers.populateChoices(entrymsg, httpServers)
    listenIP = helpers.whichIP()
    listenPort = input('[?] What port to listen on [default=443]: ', end='')
    
    if choice == 'Python UploadServer':
        print('[+] Using Python\'s http.server module as HTTP server.')
        print('[+] Starting HTTP server ...')
        cmd = f'python -m http.server -b {listenIP} {listenPort}'
        try:
            proc = Popen(cmd.split(), stdout=DEVNULL, stderr=DEVNULL)
            print('[+] HTTP server succesfully started')
        except KeyboardInterrupt:
            proc.terminate()
            exit(0)
        except:
            print('[!] Failed to start HTTP server')
            exit(1)

    # COPY FILE TO BE TRANSFERRED TO CURRENT DIRECTORY
    cmd = 'cp ' + relpath + ' tmp'
    try:
        subprocess.run(cmd, shell=True)
    except:
        print('[!] Could not temporarily copy file to current directory')

def stopHTTP():
    print('stop http')

def startListener(listenIP, listenPort):
    cmd = f'nc -nls {listenIP} -p {listenPort}'
    print(f'[+] Listening on {listenIP}:{listenPort} ...')
    try:
        run(cmd.split())
    except KeyboardInterrupt:
        exit(0)