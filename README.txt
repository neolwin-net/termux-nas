VIVO Y28 HOME NAS — INSTALLATION PACKAGE
========================================

PACKAGE CONTENTS
- app.py
- templates/base.html
- templates/login.html
- templates/dashboard.html
- templates/files.html
- static/css/style.css

REQUIREMENTS
Termux on Android, Python, Flask, Flask-WTF, and Waitress.

1. Install dependencies in Termux:
   pkg update && pkg upgrade -y
   pkg install python -y
   pip install flask flask-wtf waitress

2. Prepare Android shared-storage permission:
   termux-setup-storage

3. Create the application folders:
   mkdir -p ~/nas-server/templates ~/nas-server/static/css
   mkdir -p ~/NAS/{Documents,Pictures,Videos,Backups,Shared}

4. Copy the package files into Termux:
   Extract the ZIP on your phone, then copy:
   app.py                         -> ~/nas-server/app.py
   templates/*                    -> ~/nas-server/templates/
   static/css/style.css           -> ~/nas-server/static/css/style.css

5. Set the administrator password in the Termux session:
   export NAS_USER="admin"
   export NAS_PASSWORD="CHOOSE_A_LONG_UNIQUE_PASSWORD"

   Set these variables again after opening a new Termux session, unless
   you add them to a private startup script.

6. Check Python syntax:
   cd ~/nas-server
   python -m py_compile app.py

7. Start the NAS:
   python app.py

8. Find your phone's Wi-Fi IP address and open this from a device on the
   same trusted Wi-Fi/LAN:
   http://PHONE_LAN_IP:8080

SECURITY NOTES
- This server is intended for a trusted local network only.
- Do not configure router port forwarding for port 8080.
- Do not use it on public or untrusted Wi-Fi.
- HTTP traffic on the LAN is not encrypted. Use a trusted network.
- CSRF protection is enabled on all POST routes.
- Maximum request size is 2 GiB.
- Non-empty folders cannot be deleted by this application.
- Existing files are not overwritten during upload.
- The app accesses the Termux NAS folder and Android shared storage.
- Keep Android/Termux permissions and device lock enabled.

ADMIN PASSWORD
The app does not contain a default password. You must set NAS_PASSWORD
before starting the server.
