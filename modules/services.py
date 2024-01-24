from subprocess import Popen, DEVNULL, run
from os import mkdir
from sys import exit
from time import sleep
from shutil import rmtree
import helpers

httpUploadServers = [
    'Python'
]

def startHTTP():
    entrymsg = '[?] Which HTTP server to use:'
    choice = helpers.populateChoices(entrymsg, httpUploadServers)
    listenIP = helpers.whichIP()
    print('[?] What port to listen on [default=443]: ', end='')
    listenPort = input()
    if listenPort == '':
        listenPort = '443'
    
    if choice == 'Python':
        webroot = '/tmp/webroot'

        print('[+] Using Python\'s http.server module as HTTP server')
        print('[+] Deleting /tmp/webroot if it already exists ...')
        rmtree('/tmp/webroot', ignore_errors=True)
        print('[+] Creating temporary folder for webroot in /tmp')
        mkdir(webroot)

        print('[+] Starting HTTP server ...')
        sleep(1)
        cmd = f'python -m http.server -d {webroot} -b {listenIP} {listenPort}'
        try:
            proc = Popen(cmd.split(), stdout=DEVNULL, stderr=DEVNULL)
            print('[+] HTTP server succesfully started')
        except KeyboardInterrupt:
            proc.terminate()
            exit(0)
        except:
            print('[!] Failed to start HTTP server')
            exit(1)
    return proc, listenIP, listenPort

def stopHTTP(proc):
    sleep(1)
    print('[?] Stop HTTP server? [Y/n] ', end='')
    try:
        subterminate = input().lower()
    except KeyboardInterrupt:
        try:
            proc.terminate()
            print('\n[+] HTTP server succesfully terminated')
        except:
            print('\n[!] Could not terminate HTTP server')
        exit(0)
    if subterminate == '':
        subterminate = 'y'
    if subterminate == 'n':
        print('[!] HTTP server was left running')
    else:
        try:
            proc.terminate()
            print('[+] HTTP server succesfully terminated')
        except:
            print('[!] Could not terminate HTTP server')

    try:
        rmtree('/tmp/webroot', ignore_errors=True)
        print('[+] Successfully deleted temporary webroot')
    except:
        print('[!] Temporary webroot could not be deleted (/tmp/webroot)')

def startListener(listenIP, listenPort):
    cmd = 'nc -nls ' + listenIP + ' -p ' + listenPort
    print(f'[+] Listening on {listenIP}:{listenPort} ...')
    try:
        run(cmd.split())
    except KeyboardInterrupt:
        exit(0)