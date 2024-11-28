#!/bin/bash

version='0.557'

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
confFile="$HOME/.config/meoConnect/${0##*/}.conf"
dnsFile="$HOME/.config/meoConnect/${0##*/}.dns"
OfflineFile="$HOME/.config/meoConnect/${0##*/}.offline.mp3"
OnlineFile="$HOME/.config/meoConnect/${0##*/}.online.mp3"
OLCmd="$HOME/.config/meoConnect/${0##*/}.OLCmd"
forceSynctime=0
remLine=false

#  meoConnect.sh
#  
#  Copyright 2024 ClawsPT <claws@sapo.pt>
#----------------------------------------------------------------------- 
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#----------------------------------------------------------------------- 

encryptPasswd () {

#Using python to encrypt password
#Using part of ravemir code - https://github.com/ravemir/meo-wifi-login
	
PYCMD=$(cat <<EOF

from __future__ import absolute_import
from __future__ import print_function

import os
import sys
import getopt
import getpass
import json
import hashlib
import base64
import urllib
if sys.version_info >= (3, 0):
  import urllib.request
  urllib = urllib.request

### Non-builtin imports
try:
  import requests
except ImportError:
  pass

try:
  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
  from cryptography.hazmat.primitives.padding import PKCS7
  from cryptography.hazmat.backends import default_backend
except ImportError:
  pass

try:
  import pyaes
except ImportError:
  pass

## Check dependency requirements
missing_msg = []
fail = False

# Need either cryptography or pyaes
if "cryptography" not in sys.modules and "pyaes" not in sys.modules:
  fail = True
  missing_msg += [ "cryptography or pyaes" ]

if fail == True:
  print("Error: missing dependencies.")
  print("Please install the following modules: " + ", ".join(missing_msg))
  sys.exit(1)

### Encryption functions

def encrypt_pyaes(key, iv, msg):
  """encrypt using pyaes module"""
  mode = pyaes.AESModeOfOperationCBC(key, iv=iv)
  encrypter = pyaes.blockfeeder.Encrypter(mode)
  return encrypter.feed(msg) + encrypter.feed()

def encrypt_cryptography(key, iv, msg):
  """encrypt using cryptography module"""
  padder = PKCS7(128).padder()
  msg_padded = padder.update(msg.encode("utf8")) + padder.finalize()

  cipher = Cipher(algorithms.AES(key),
                  modes.CBC(iv),
                  backend=default_backend())
  encryptor = cipher.encryptor()
  return encryptor.update(msg_padded) + encryptor.finalize()

def encrypt(key, iv, msg):
  """Encrypt msg using AES in CBC mode and PKCS#7 padding.

  Will use either the cryptography or pyaes module, whichever is
  available.

  """
  if "cryptography" in sys.modules:
    return encrypt_cryptography(key, iv, msg)
  elif "pyaes" in sys.modules:
    return encrypt_pyaes(key, iv, msg)

def encrypt_password(ip, password):
  """Encrypt the password like the captive portal's Javascript does"""
  # Salt for PBKDF2
  salt = bytearray.fromhex("77232469666931323429396D656F3938574946")
  # Initialization vector for CBC
  iv = bytes(bytearray.fromhex("72c4721ae01ae0e8e84bd64ad66060c4"))
  
  # Generate key from IP address
  key = hashlib.pbkdf2_hmac("sha1", ip.encode("utf8"), salt, 100, dklen=32)
  
  # Encrypt password
  ciphertext = encrypt(key, iv, password)
  
  # Encode to Base64 (explicitly convert to string for Python 2/3 compat)
  ciphertext_b64 = base64.b64encode(ciphertext).decode("ascii")
  
  return urllib.quote(ciphertext_b64, safe='')

def main():
  # Retrieve environment variables

  ip=os.getenv('MEO_WIFI_USER', '')
  passwd=os.getenv('MEO_WIFI_PASSWORD', '')

  # Parse the arguments
  opts, args = getopt.getopt(sys.argv[1:], "hxu:p:")
  for (opt, arg) in opts:
    if opt == '-p':
      passwd = arg
    elif opt == '-u':
      ip = arg
  
  print(encrypt_password(ip, passwd))

if __name__ == '__main__':
  main()
EOF
)

ip=$(ip addr show $wifiif | awk '/inet / {print $2}')
ip=${ip%/*}	

echo $(python3 -c "$PYCMD" -u $ip -p $passwd)	
	
}

vpnConnect () {
	if [[ $(ifconfig | grep "proton") || $(ifconfig | grep "ipv6leakintrf") ]]; then
		foo=$(timeout --preserve-status -k 5 30 protonvpn-cli d)
	fi
	vpnConn=$(timeout --preserve-status -k 5 45 protonvpn-cli connect --cc NL --protocol tcp | grep "Successfully connected")
	if [[ "$vpnConn" ]]; then
		serverStatus=$(protonvpn-cli s)
		serverLoad=$(echo "$serverStatus" | grep "Server Load")
		serverLoad=$(echo $serverLoad | grep -o -E '[0-9]+')
		serverLoad="$serverLoad%"
		serverName=$(echo "$serverStatus" | grep "Server:")
		serverName=${serverName:10}
		echo -e "\033[1;92mDone.\033[0m"
	else
		echo -e "\033[1;91mConnection failed.\033[0m"
	fi
}

vpnDisconnect () {

	echo -n "Disconnecting ProtonVPN: "
	if [[ $(ifconfig | grep proton) ]] ; then
		vpnDisConn=$(timeout --preserve-status -k 5 30 protonvpn-cli d | grep "Successfully disconnected")
		if [[ "$vpnDisConn" ]]; then
			echo -e "\033[1;92mSuccessfully disconnected.\033[0m"
		else
			echo -e "\033[1;92mTimedout. (This is normal)\033[0m"
		fi		
	else
		echo "Not commected."
	fi

	echo -n "Setting DNS server: "
	setDNS
	echo -e "\033[1;92mDone.\033[0m"
}

connectMeoWiFi () {
		mpg321 -q $OnlineFile > /dev/null 2>&1 &
		if [ "$connectionVer" == "v2" ] ; then
			echo "Reconnecting to $(iwconfig $wifiif | sed -n 's/.*Access Point: \([0-9\:A-F]\{17\}\).*/\1/p')"
			#echo $rPasswd | sudo -S ifconfig $wifiif down > /dev/null 2>&1
			#echo $rPasswd | sudo -S ifconfig $wifiif up > /dev/null 2>&1
			nmcli connection up "$wifiap" ifname "$wifiif" > /dev/null 2>&1
		fi
		
		echo "Login into MEO WiFi...."
		connect=$(connectMeoWiFiv1)
		if [ "$connect" == 'null' ] || [ "$connect" == '"Já se encontra logado"' ] ; then
			echo -e "\033[1;92mSuccessfully connected\033[0m to MEO WiFi: $(iwconfig $wifiif | sed -n 's/.*Access Point: \([0-9\:A-F]\{17\}\).*/\1/p')."
			remLine=false
		#Start VPN
			if $vpn ; then
				echo -n "Connecting to ProtonVPN: "
				vpnConnect
				remLine=false
			fi					
		elif [ "$connect" == '"OUT OF REACH"' ] ; then
			echo -e "Someting went wrong: \033[1;91m$connect\033[0m"
			echo "Trying v2 login..."
			connectMeoWiFiv2
			connectionVer='v2'
			remLine=false
		elif [ "$connect" == '"De momento não é possível concretizar o seu pedido. Por favor, tente mais tarde."' ] || [ "$connect" == "unavailable" ] ; then
			echo -e "Someting went wrong, retrying in 5s...\n        \033[1;91m$connect\033[0m"
			sleep 5
			#echo -e "-----------\n$json ----------\n"
			forceSynctime=1
			remLine=false
			connectMeoWiFi
		else
			echo -e "Someting went wrong: \033[1;91m$connect\033[0m"
			sleep 2
		# Get BSSID List.
			echo $rPasswd | sudo -S ifconfig $wifiif up > /dev/null 2>&1
			echo -n "Scanning for MEO WiFi networks: " 
			echo $rPasswd | sudo -S nmcli --fields SSID,BSSID device wifi list ifname $wifiif --rescan yes | grep "MEO-WiFi" > $HOME/.config/meoConnect/${0##*/}.lst
			sed -i 's/MEO-WiFi//g' $HOME/.config/meoConnect/${0##*/}.lst
			sed -i 's/ //g' $HOME/.config/meoConnect/${0##*/}.lst
			echo -e " $(wc -l < $HOME/.config/meoConnect/${0##*/}.lst) APs found. \033[1;92mDone.\033[0m"
			echo "Disconecting from $(iwconfig $wifiif | sed -n 's/.*Access Point: \([0-9\:A-F]\{17\}\).*/\1/p')."
		# Connecting to BSSID list.	
			bssid=""
			while read p; do
				echo $rPasswd | sudo -S ifconfig $wifiif down > /dev/null 2>&1
				echo -n "Connecting to $p: "
				echo $rPasswd | sudo -S nmcli connection modify $wifiap 802-11-wireless.bssid "$p"
				echo $rPasswd | sudo -S ifconfig $wifiif up > /dev/null 2>&1
				nmcli connection up "$wifiap" ifname "$wifiif" > /dev/null 2>&1
				ip=$(ip addr show $wifiif | awk '/inet / {print $2}')
				if [[ "$ip" != "" ]] ; then
					echo -e "\033[1;92mDone.\033[0m"
					break
				else
					echo -e "\033[1;91mFail.\033[0m"
				fi
			done <$HOME/.config/meoConnect/${0##*/}.lst	
			forceSynctime=1
			remLine=false
			connectMeoWiFi
		fi
}

connectMeoWiFiv1 () {

	ip=$(ip addr show $wifiif | awk '/inet / {print $2}')
	ip=${ip%/*}
	encPwd=$(encryptPasswd)
	connRetryTemp=$(expr $connRetry + 1 )
	json=""	
	while [ "$json" = "" -a "$connRetryTemp" -ge 1 ] ;do
		json=$(curl $curlCmd "https://servicoswifi.apps.meo.pt/HotspotConnection.svc/Login?username="$user"&password="$encPwd"&navigatorLang=pt")
		connRetryTemp=$(expr $connRetryTemp - 1 )
	done

	if [[ $(echo $json | grep "unavailable" ) ]] ; then
		echo '"Unavailable"'
	else
		error=$(echo $json | jq '.error')
		if [[ "$error" ]]; then
			echo "$error"
		else
			echo "Connection timeout. $json"
		fi
	fi
}

connectMeoWiFiv2 () {

	ip=$(ip addr show $wifiif | awk '/inet / {print $2}')
	ip=${ip%/*}	
	url="https://meowifi.meo.pt/wifim-scl/service/session-status"
	body="{\"ipAddress\":\"$ip\"}"

	# Send a POST request and parse the session ID from the JSON response
	sessionId=$(curl $curlCmd -X POST -H "Content-Type: application/json" -d "$body" "$url")
	sessionId=$(echo $sessionId | jq -r '.sessionId')
		
	if [ "$sessionId" != "null" ] ; then
	# Construct the URL for session login
		url="https://meowifi.meo.pt/wifim-scl/service/${sessionId}/session-login"
	# Construct the login request body
		login_body="{\"userName\":\"$user\",\"password\":\"$passwd\",\"ipAddress\":\"$ip\",\"sessionId\":\"$sessionId\",\"loginType\":\"login\"}"
	# Send a POST request for login
		response=$(curl $curlCmd -X POST -H "Content-Type: application/json" -d "$login_body" "$url")
		echo "Connected using v2"
	else
		echo "NO Session Id Found..."
	fi
}

editSettings () {

# User Password
	echo -n "Please enter User password ($rPasswd):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		rPasswd=$sTemp
	fi
	clear
	
# WiFi Connection Name
	nmcli connection show | grep "wifi"
	echo -n "WiFi Connection Name ($wifiap):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		wifiap=$sTemp
	fi
	
# Wireless device name
	echo -n "Wireless device name ($wifiif):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		wifiif=$sTemp
	fi
	
# Meo WiFi username
	echo -n "Meo WiFi username ($user):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		user=$sTemp
	fi
	
# Meo WiFi Password
	echo -n "Meo WiFi Password ($passwd):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		passwd=$sTemp
	fi
	
# Time in seconds between network checks
	echo -n "Time in seconds between network checks ($recheckTime):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		recheckTime=$sTemp
	fi
	
# Use ProtonVPN
	echo -n "Use ProtonVPN (true/false) ($vpn):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		vpn=$sTemp
	fi
	
# VPN max load %
	echo -n "VPN max load ($vpnMload):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		vpnMload=$sTemp
	fi
	
# Number of retries
	echo -n "Number of retries ($connRetry):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		connRetry=$sTemp
	fi

# Text Editor
	editor='geany'
	
	echo ""
	echo "Note: To Change Command to run on successful login edit"
	echo "    : $OLCmd"
	echo "    : two values are sent to the scrip"
	echo "    : 1-Connection Version Version, 2-BSSID"
	echo ""
	echo "Note: To Change DNS config edit $dnsFile"
	echo ""
	
	echo -n "Save Configuration (y/n):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		if [ $sTemp = "y" ] ; then
			saveSettings
			echo "Reloading script"
			sleep 1
			exec $SCRIPT_DIR/meoConnect.sh 
			mpg321 -q $OfflineFile
		fi
	fi
}

saveSettings () {

echo "Saving Settings into $confFile"	
FILE="$confFile"
mkdir -p $HOME/.config/meoConnect
touch $FILE

/bin/cat <<EOF >$FILE
# -------------------------------------- meoConnect Setup file -------------------------------

# User Password
# If left empty it will be asked at script start
rPasswd='$rPasswd'

# WiFi Connection Name
# Use 'nmcli connection show' to show saved connections
wifiap='$wifiap'

# Wireless device name
wifiif='$wifiif'

# Meo WiFi username
user='$user'

# Meo WiFi Password
passwd='$passwd'

# Time in seconds between network checks
recheckTime='$recheckTime'

# Use ProtonVPN
vpn='$vpn'

# VPN max load %
vpnMload='$vpnMload'

# Text Editor
editor='$editor'

# curl command
curlCmd='-s --interface $wifiif --connect-timeout 20 --max-time 10 -H "Cache-Control: no-cache, no-store, must-revalidate, Pragma: no-cache, Expires: 0"'

# Number of retries
connRetry='$connRetry'

EOF
}

setDNS () {
	
echo $rPasswd | sudo -S cp -f $dnsFile /etc/resolv.conf  > /dev/null 2>&1
}

syncTime () {
	
	checkUpdate
	echo -n "Getting Connection Time: "
	meoTime=""
	json=""	
	remLine=false
	while [[ ! "$meoTime" ]] ;do	 
		json=$(curl $curlCmd "https://servicoswifi.apps.meo.pt/HotspotConnection.svc/GetState?mobile=false")
		
		if [[ $(echo $json | grep "unavailable" ) ]] ; then
			echo "----------------- Debug: $json"
			json=""
		fi

		json=$(echo $json | jq '.Consumption')
		meoTime=$(echo $json | jq -r '.Time')
	done
	if [ "$meoTime" != "null" ]; then
		meoTime="$meoTime:00"
		echo -e "\033[1;92mv1\033[0m: $meoTime"
		meoTime=$(date -d "1970-01-01 $meoTime Z" +%s)
		currenttime=$(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s)
		starttime=$(($currenttime - $meoTime))
		connectionVer='v1'
		XDG_RUNTIME_DIR=/run/user/$(id -u) notify-send  "Successfully connected to MEO WiFi"	
		echo -n -e "Running OLCmd          : \033[0;96m"
		echo $($OLCmd $connectionVer $(iwconfig $wifiif | sed -n 's/.*Access Point: \([0-9\:A-F]\{17\}\).*/\1/p'))
		echo -e "\033[0m                       : \033[1;92mDone.\033[0m"
		echo "-------------------------------------------------------------------------------"
	else
		echo -e "\033[1;91mv1: Fail.\033[0m"
		echo -n "                         "
		ip=$(ip addr show $wifiif | awk '/inet / {print $2}')
		ip=${ip%/*}	
		url="https://meowifi.meo.pt/wifim-scl/service/session-status"
		body="{\"ipAddress\":\"$ip\"}"

		# Send a POST request and parse the session ID from the JSON response
		sessionId=$(curl $curlCmd -X POST -H "Content-Type: application/json" -d "$body" "$url")
		#echo $sessionId
		sessionInfo=$(echo $sessionId | jq '.sessionInfo' )
		meoTime=$(echo $sessionInfo | jq -r '.sessionInitialDate')
		if [ "$meoTime" != "null" ]; then
			meoTime="${meoTime:11:8}"
			starttime=$(date -d "1970-01-01 $meoTime Z" +%s)
			currenttime=$(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s)
			totaltime=$(($currenttime - $starttime))
			echo -e "\033[1;92mv2\033[0m: $(date -d "1970-01-01 + $totaltime seconds" "+%H:%M:%S")"
			connectionVer='v2'
			XDG_RUNTIME_DIR=/run/user/$(id -u) notify-send  "Successfully connected to MEO WiFi"		
			echo -n -e "Running OLCmd          : \033[0;96m"
			echo $($OLCmd $connectionVer $(iwconfig $wifiif | sed -n 's/.*Access Point: \([0-9\:A-F]\{17\}\).*/\1/p'))
			echo -e "\033[0m                       : \033[1;92mDone.\033[0m"
			echo "-------------------------------------------------------------------------------"
		else
			starttime=$(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s)
			echo -e "\033[1;91mv2: Fail.\033[0m"
			echo "-------------------------------------------------------------------------------"
		fi
	fi
	}

checkUpdate () {

	echo -n "Checking for updates   : "
	gitVer=$(curl -H "Cache-Control: no-cache, no-store, must-revalidate, Pragma: no-cache, Expires: 0" https://raw.githubusercontent.com/ClawsPT/meoConnect/main/meoConnect.sh -s -r 13-28 | grep "version")
	if [ "$gitVer" ] ; then
		if [ "$gitVer" == "version='$version'" ] ; then
			echo -e "\033[1;92mUpdated.\033[0m ($gitVer)"
		else
			echo -e "\033[1;92mUpdate found.\033[0m ($gitVer)"
			echo -e "Downloading update."
			curl -H "Cache-Control: no-cache, no-store, must-revalidate, Pragma: no-cache, Expires: 0" --progress-bar https://raw.githubusercontent.com/ClawsPT/meoConnect/main/meoConnect.sh -o "$SCRIPT_DIR/${0##*/}"
			curl -H "Cache-Control: no-cache, no-store, must-revalidate, Pragma: no-cache, Expires: 0" --progress-bar https://raw.githubusercontent.com/ClawsPT/meoConnect/main/offline.mp3 -o "$OfflineFile"
			curl -H "Cache-Control: no-cache, no-store, must-revalidate, Pragma: no-cache, Expires: 0" --progress-bar https://raw.githubusercontent.com/ClawsPT/meoConnect/main/online.mp3 -o "$OnlineFile"			
			echo -e "Download: \033[1;92mDone.\033[0m"
			chmod +x "$SCRIPT_DIR/"${0##*/}
			echo "Restarting script."
			mpg321 -q $OfflineFile
			sleep 5
			exec "$SCRIPT_DIR/"${0##*/}
		fi
	else
		echo -e "\033[1;91mFail to check.\033[0m"
	fi
}

createDNSfile () {
	
touch $dnsFile

/bin/cat <<EOF >$dnsFile
# This file was written by meoConnect v$version)

# Google DNS
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 127.0.0.53
options timeout:3
options attempts:2
options edns0 trust-ad
EOF

}

startUp () {
	
if [ ! -f $confFile ]; then
    echo -e "Checking Config file   : \033[1;91mFail, creating new: \033[0m"
    editSettings
	exit
else
	echo -e "Checking Config file   : \033[1;92mDone.\033[0m"
fi

if [ ! -f $dnsFile ]; then
    echo -e -n "Checking DNS conf file : \033[1;91mFail, creating new: \033[0m"
    createDNSfile
    echo -e "\033[1;92mDone.\033[0m"
else
	echo -e "Checking DNS conf file : \033[1;92mDone.\033[0m"
fi
if [ ! -f $OLCmd ]; then
    echo -e -n "Checking OLCmd file    : \033[1;91mFail, creating new: \033[0m"
    touch $OLCmd
    chmod +x $OLCmd
    echo -e "\033[1;92mDone.\033[0m :"
else
	echo -e "Checking OLCmd file    : \033[1;92mDone.\033[0m"
fi
if [ ! -f $OfflineFile ]; then
    echo -e "Checking Offline MP3   : \033[1;91mFail\033[0m, Downloading."
	curl -H "Cache-Control: no-cache, no-store, must-revalidate, Pragma: no-cache, Expires: 0" --progress-bar https://raw.githubusercontent.com/ClawsPT/meoConnect/main/offline.mp3 -o "$OfflineFile"
	echo -e "Download: \033[1;92mDone.\033[0m"
else
	echo -e "Checking Offline MP3   : \033[1;92mDone.\033[0m"
fi
if [ ! -f $OnlineFile ]; then
    echo -e "Checking Online MP3    : \033[1;91mFail\033[0m, Downloading."
	curl -H "Cache-Control: no-cache, no-store, must-revalidate, Pragma: no-cache, Expires: 0" --progress-bar https://raw.githubusercontent.com/ClawsPT/meoConnect/main/online.mp3 -o "$OnlineFile"
	echo -e "Download: \033[1;92mDone.\033[0m"
else
	echo -e "Checking Online MP3    : \033[1;92mDone.\033[0m"
fi

source $confFile
echo -e "Loading Configuration  : \033[1;92mDone.\033[0m"
echo -n "Checking Dependencies  : "
for name in protonvpn-cli geany mpg321 vnstat curl jq awk notify-send
	do
	  [[ $(which $name 2>/dev/null) ]] || { echo -en "\n$name needs to be installed. Use 'sudo apt-get install $name'";deps=1; }
	done
[[ $deps -ne 1 ]] && echo -e "\033[1;92mDone.\033[0m" || { echo -en "\nInstall the above and rerun this script\n";exit 1; }

echo -n "Checking User  "
rTest=$(echo $rPasswd | su $(whoami) -c 'echo -e "\033[1;92mDone.\033[0m"')
rTest=$(echo $rTest | grep "Done.")
echo $rTest

if [[ ! $rTest ]]; then
	rPasswd=""
fi

if [ ! $rPasswd ] ; then
	echo -n "Please enter User password:"
	read -rs rPasswd
	echo -n "Checking User  "
	rTest=$(echo $rPasswd | su $(whoami) -c 'echo -e "\033[1;92mDone.\033[0m"')
	rTest=$(echo $rTest | grep "Done.")
	if [[ ! $rTest ]]; then
		echo "Invalid Password"
		exit
	fi
	saveSettings
fi
echo -n "Setting DNS server     : "
setDNS
echo -e "\033[1;92mDone.\033[0m"
echo -n "Checking Connection    : "
netStatus=""
netStatus=$(echo $(curl $curlCmd --head  --request GET www.google.com |grep "HTTP/"))
if [[ $(echo $netStatus | grep "Moved") ]]; then #Moved -> redirected to login portal
	netStatus=""
fi

if [[ "$netStatus" ]]; then
	echo -e "\033[1;92mConnected\033[0m to $(iwconfig $wifiif | sed -n 's/.*Access Point: \([0-9\:A-F]\{17\}\).*/\1/p')"
	if [[ $(ifconfig | grep proton) ]] ; then
		
		if $vpn ; then
			echo -e "Checking ProtonVPN     : \033[1;92mConnected.\033[0m"
		else
			echo -e -n "Checking ProtonVPN     : \033[1;91mWrong state, \033[0mDisconecting: "
			vpnDisconnect
		fi	
	else
		if $vpn ; then
			echo -e -n "Checking ProtonVPN     : \033[1;91mWrong state, \033[0m Conecting: "
			vpnConnect
		else
			echo -e "Checking ProtonVPN     : \033[1;92mDisconnected.\033[0m"
		fi
	fi
	syncTime
else
	echo -e "\033[1;91mDisconnected.\033[0m"
	starttime=$(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s)
fi
echo "    $(date "+%Y-%m-%d - %H:%M:%S") - Starting script"
echo -e "-------------------------------------------------------------------------------"

}

clear
echo "-------------------------------------------------------------------------------"
echo "|                        MEO Wifi AutoConnect v$version                          |"
echo "-------------------------------------------------------------------------------"
startUp

# -------------------------------- Start Loop ---------------------------------------

while true ; do
	currenttime=$(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s)
	totaltime=$(($currenttime - $starttime))
#-------------------------------- Check Connection ----------------------------------
	netStatus=""
	connRetryTemp=$(expr $connRetry + 1 )
	while [ "$netStatus" = "" -a "$connRetryTemp" -ge 1 ] ;do
		netStatus=$(echo $(curl $curlCmd --head www.google.com | grep "HTTP/"))
		netStatus=$(printf "$netStatus" | sed 's/\r//g' | sed 's/HTTP\/1.1 //g' | sed 's/HTTP\/1.0 //g')
		if [[ $(echo $netStatus | grep "Moved") ]]; then #Moved -> redirected to login portal
			echo "-------------------------------------------------------------------------------"
			echo -e "    \033[1;91mOFFLINE\033[0m - $(date "+%H:%M:%S") - \033[1;92mRedirected to login portal\033[0m - $netStatus"
			echo "-------------------------------------------------------------------------------"
			mpg321 $OfflineFile > /dev/null 2>&1 &
			connectMeoWiFi
			sleep 5
			forceSynctime=1
			remLine=false
			netStatus=""
			continue
		fi
		connRetryTemp=$(expr $connRetryTemp - 1 )
	done
# ---------------------------------- ONLINE -----------------------------------------
	
	if [[ "$netStatus" ]]; then
	#Get ProtonVPN server stats
		if $vpn  ; then
			serverStatus=$(protonvpn-cli s)
			serverLoad=$(echo "$serverStatus" | grep "Server Load")
			serverLoad=$(echo $serverLoad | grep -o -E '[0-9]+')
			serverName=$(echo "$serverStatus" | grep "Server:")
			serverName=${serverName:10}
			if [[ ! "$serverLoad" ]]; then
				if $vpn  ; then
					echo -n "ProtonVPN is disconnected, reconnecting: "
					vpnConnect
					echo "-------------------------------------------------------------------------------"
					remLine=false
				else
					serverLoad="Offline"
				fi
			elif [ $serverLoad -gt $vpnMload ]; then
				echo "-------------------------------------------------------------------------------"
				echo -n "VPN Load over $vpnMload % ($serverLoad%), connecting to new server: "
				vpnConnect
				echo "-------------------------------------------------------------------------------"
				remLine=false
			else
				serverLoad="$serverLoad%"
			fi
		else
			serverName="VPN"
			serverLoad="Offline"
		fi
	#Get traffic and cpu
		cpuuse=$(cat <(grep 'cpu ' /proc/stat) <(sleep 1 && grep 'cpu ' /proc/stat) | awk -v RS="" '{printf "%3.0f%\n", ($13-$2+$15-$4)*100/($13-$2+$15-$4+$16-$5)}')
		IN=$(vnstat $wifiif -d | (tail -n3))
		INR=${IN//estimated}
		arrOUT=(${INR//|/ })
	#Get time from server.
		if [ $forceSynctime = 1 ] ; then
			syncTime
			totaltime=$(($currenttime - $starttime))
			forceSynctime=0
		fi
	#Echo status line.
		if [ "$netStatus" != "200 OK" ] ; then
			remLine=true
		fi
		if [ "$remLine" == "true" ] ; then
			echo -ne '\e[1A\e[K'
		fi
		echo -n -e " $connectionVer|T:$(printf "%02d" $(($(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s) - $currenttime)))|\033[0;93m$(date -d "1970-01-01 + $totaltime seconds" "+%H:%M:%S")\033[0m|U/D ${arrOUT[5]} ${arrOUT[6]}"
		echo -n "|$serverName $serverLoad|CPU$cpuuse" $(cat /sys/class/thermal/thermal_zone0/temp | sed 's/\(.\)..$/.\1°C/')"|"
		echo $netStatus	
	else

# -------------------------------------- OFFLINE ------------------------------------
		
		echo "-------------------------------------------------------------------------------"
		echo -e "    \033[1;91mOFFLINE\033[0m - $(date "+%H:%M:%S") | $connectionVer | T:$(printf "%02d" $(($(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s) - $currenttime))) | $(date -d "1970-01-01 + $totaltime seconds" "+%H:%M:%S")"
		mpg321 $OfflineFile > /dev/null 2>&1 &
		echo "-------------------------------------------------------------------------------"
		forceSynctime=1
		vpnDisconnect
	#Login into MEO-WiFi v1/v2
		connectMeoWiFi
		continue
	fi

# ----------------------------------- Pause script ----------------------------------

	skipTime=$(($recheckTime - ($(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s) - $currenttime + 1)))
	skip=""
	
	while [ "$skip" != "f" -a "$skipTime" -ge 0 ] ;do
		linkQuality=$(iwconfig wlan1 | awk -F= '/Quality/ {print $2}' | awk -F/ '{print $1}')
		echo -n -e ">> T-$skipTime""s , S:$linkQuality% , \033[4;1mF\033[0morce , \033[4;1mV\033[0mPN , c\033[4;1mH\033[0mange AP , \033[4;1mC\033[0monfig , \033[4;1mS\033[0mtatus , \033[4;1mR\033[0meload , \033[4;1mQ\033[0muit <<"
		read -rsn1 -t 1 skip
		echo -e -n "\r\033[K"
		
		if [[ $skip = "" ]]; then
			skipTime=$(expr $skipTime - 1 )
		elif [[ $skip = "v" ]]; then
			echo "-------------------------------------------------------------------------------"
			if ! $vpn ; then
				echo -n "Connecing to ProtonVPN: "
				vpnConnect
				vpn=true
				skip="f"
			else
				vpnDisconnect
				vpn=false
				skip="f"
			fi
			remLine=false
			echo -e "-------------------------------------------------------------------------------\n"
		elif [[ $skip = "h" ]]; then

			# Get BSSID List.
				echo -n "Scanning WiFi networks: " 				
				echo $rPasswd | sudo -S ifconfig $wifiif up > /dev/null 2>&1
				echo $rPasswd | sudo -S nmcli --fields SSID,BSSID,CHAN,BARS,SIGNAL device wifi list ifname $wifiif --rescan yes | grep "MEO-WiFi" | sort > $HOME/.config/meoConnect/${0##*/}.lst
				#sed -i 's/MEO-WiFi             //g' $HOME/.config/meoConnect/${0##*/}.lst
				#sed -i 's/  //g' $HOME/.config/meoConnect/${0##*/}.lst
				echo -e "\033[1;92mDone.\033[0m $(wc -l < $HOME/.config/meoConnect/${0##*/}.lst) APs found."
	
			# Connecting to BSSID list.
				echo "     # |                 BSSID                     |Chan| Signal   "
				cat -b $HOME/.config/meoConnect/${0##*/}.lst
				read -p "connect to: " lineNumber
				
				bssid=$(sed -n "$lineNumber"p $HOME/.config/meoConnect/${0##*/}.lst)
				bssid=$(echo $bssid | sed -n 's/.*MEO-WiFi \([0-9\:A-F]\{17\}\).*/\1/p')
				bssid=$(echo $bssid | cut -c1-17)
				echo "Disconecting from $(iwconfig $wifiif | sed -n 's/.*Access Point: \([0-9\:A-F]\{17\}\).*/\1/p')."
				echo $rPasswd | sudo -S ifconfig $wifiif down > /dev/null 2>&1
				echo -n "Connecting to $bssid: "
				echo $rPasswd | sudo -S nmcli connection modify $wifiap 802-11-wireless.bssid "$bssid"
				echo $rPasswd | sudo -S ifconfig $wifiif up > /dev/null 2>&1
				nmcli connection up "$wifiap" ifname "$wifiif" > /dev/null 2>&1
				ip=$(ip addr show $wifiif | awk '/inet / {print $2}')
				if [[ "$ip" != "" ]] ; then
					echo -e "\033[1;92mDone.\033[0m"
				else
					echo -e "\033[1;91mFail.\033[0m"
				fi
				
				forceSynctime=1
				remLine=false
				connectMeoWiFi
				break

		elif [[ $skip = "c" ]]; then
			editSettings
# ----------------------------------------------- TESTE -----------------------------------------
		elif [[ $skip = "t" ]]; then
			echo "------------------------------- TESTE -----------------------------------------"

			
				mpg321 -q $OnlineFile > /dev/null 2>&1 &

 
			echo "------------------------------- TESTE -----------------------------------------"
# ----------------------------------------------- TESTE -----------------------------------------
		elif [[ $skip = "u" ]]; then
			checkUpdate
		elif [[ $skip = "s" ]]; then
			echo "-------------------------------------------------------------------------------"
			json=$(curl $curlCmd "https://servicoswifi.apps.meo.pt/HotspotConnection.svc/GetState?mobile=false")
			echo "Corrent connection: $(iwconfig $wifiif | sed -n 's/.*Access Point: \([0-9\:A-F]\{17\}\).*/\1/p')"
			json=$(echo $json | jq -r '.Consumption')
			echo "DownstreamMB: $(echo $json | jq -r '.DownstreamMB')"
			echo "UpstreamMB: $(echo $json | jq -r '.UpstreamMB')"
			syncTime
			echo ""
			remLine=false
		elif [[ $skip = "q" ]]; then
			exit
		elif [[ $skip = "r" ]]; then
			echo "Reloading script"
			sleep 1
			mpg321 -q $OfflineFile
			exec "$SCRIPT_DIR/"${0##*/}
			exit
		fi	
	done
	remLine=true
done
