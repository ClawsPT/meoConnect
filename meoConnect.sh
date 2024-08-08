#!/bin/bash

version='0.431'

connectionVer='v1'
confFile=$HOME/.config/meoConnect/${0##*/}.conf
forceSynctime=0

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
	vpnConn=$(timeout --preserve-status -k 5 45 protonvpn-cli connect --cc NL --protocol udp | grep "Successfully connected")
	if [[ "$vpnConn" ]]; then
		serverStatus=$(protonvpn-cli s)
		serverLoad=$(echo "$serverStatus" | grep "Server Load")
		serverLoad=$(echo $serverLoad | grep -o -E '[0-9]+')
		serverLoad="$serverLoad%"
		serverName=$(echo "$serverStatus" | grep "Server:")
		serverName=${serverName:10}
		echo "Successfully connected."
	else
		echo "Connection failed."
	fi
}

vpnDisconnect () {

	echo -n "Disconnecting ProtonVPN: "
	if [[ $(ifconfig | grep proton) ]] ; then
		vpnDisConn=$(timeout --preserve-status -k 5 30 protonvpn-cli d | grep "Successfully disconnected")
		if [[ "$vpnDisConn" ]]; then
			echo "Successfully disconnected."
		else
			echo "Timedout. (This is normal)"
		fi		
	else
		echo "Not commected."
	fi

	echo "Resetting DNS"
	setDNS
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
	error=$(echo $json | jq '.error')
	if [[ "$error" ]]; then
		echo "$error"
	else
		echo "Connection timeout. ($connRetryTemp) $json"
	fi
}

connectMeoWiFiv2 () {

	ip=$(ip addr show $wifiif | awk '/inet / {print $2}')
	ip=${ip%/*}	
	url="https://meowifi.meo.pt/wifim-scl/service/session-status"
	body="{\"ipAddress\":\"$ip\"}"

	# Send a POST request and parse the session ID from the JSON response
	sessionId=$(curl $curlCmd -X POST -H "Content-Type: application/json" -d "$body" "$url")
	# Get start time
	sessionInfo=$(echo $sessionId | jq '.sessionInfo' )
	meoTime=$(echo $sessionInfo | jq -r '.sessionInitialDate')
	if [ "$meoTime" != "null" ]; then
		meoTime="${meoTime:11:8}"
		starttime=$(date -d "1970-01-01 $meoTime Z" +%s)
	else
		starttime=$(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s)
	fi
	
	sessionId=$(echo $sessionId | jq -r '.sessionId')
		
	if [ $sessionId != 'null' ] ; then
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
	
# VPN max load %
	echo -n "Command to run on successful login ($onlineCommand):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		onlineCommand=$sTemp
	fi
	
# Text Editor
	editor='geany'

	echo -n "Save Configuration (y/n):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		if [ $sTemp = "y" ] ; then
			saveSettings
			echo "Reloading script"
			sleep 1
			exec $SCRIPT_DIR/meoConnect.sh 
			mpg321 -q $SCRIPT_DIR/alarm.mp3
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

#onlineCommand
onlineCommand='$onlineCommand'

EOF
}

setDNS () {
	
FILE="$HOME/.config/meoConnect/resolv.conf"	
touch $FILE

/bin/cat <<EOF >$FILE
# This file was written by meoConnect v$version)

# Google DNS
nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 127.0.0.53
options timeout:3
options attempts:2
options edns0 trust-ad
EOF

echo $rPasswd | sudo -S cp -f $FILE /etc/resolv.conf  > /dev/null 2>&1
rm $FILE
}

syncTime () {

	echo -n "Getting Connection Time: -> v1: "
	meoTime=""
	json=""	
	while [[ ! "$meoTime" ]] ;do	 
		json=$(curl $curlCmd "https://servicoswifi.apps.meo.pt/HotspotConnection.svc/GetState?mobile=false")
		json=$(echo $json | jq '.Consumption')
		meoTime=$(echo $json | jq -r '.Time')
	done

	if [ "$meoTime" != "null" ]; then
		meoTime="$meoTime:00"
		echo "$meoTime"
		meoTime=$(date -d "1970-01-01 $meoTime Z" +%s)
		currenttime=$(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s)
		starttime=$(($currenttime - $meoTime))
		connectionVer='v1'
	else
		echo "Fail."
		echo -n "                         -> v2: "
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
			echo "$meoTime"
			starttime=$(date -d "1970-01-01 $meoTime Z" +%s)
			connectionVer='v2'
		else
			starttime=$(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s)
			echo "Fail."
		fi
	fi
	}
clear

echo "-------------------------------------------------------------------------------"
echo "|                         MEO Wifi AutoConnect v$version                         |"
echo "-------------------------------------------------------------------------------"

source $confFile
echo "Loading Configuration($confFile): Done."
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo -n "Checking Dependencies  : "
for name in protonvpn-cli geany mpg321 vnstat curl jq awk notify-send
	do
	  [[ $(which $name 2>/dev/null) ]] || { echo -en "\n$name needs to be installed. Use 'sudo apt-get install $name'";deps=1; }
	done
	[[ $deps -ne 1 ]] && echo "Done." || { echo -en "\nInstall the above and rerun this script\n";exit 1; }

if [ ! -f $confFile ]; then
    echo "Configuration File not found..."
    editSettings
	exit
fi

echo -n "Checking User  "
rTest=$(echo $rPasswd | su $(whoami) -c 'echo "Done."')
rTest=$(echo $rTest | grep "Done.")
echo $rTest

if [[ ! $rTest ]]; then
	rPasswd=""
fi

if [ ! $rPasswd ] ; then
	echo -n "Please enter User password:"
	read -rs rPasswd
	echo -n "Checking User  "
	rTest=$(echo $rPasswd | su $(whoami) -c 'echo "Done."')
	rTest=$(echo $rTest | grep "Done.")
	if [[ ! $rTest ]]; then
		echo "Invalid Password"
		exit
	fi
	saveSettings
fi

echo -n "Checking Connection    : "
netStatus=""
netStatus=$(echo $(curl $curlCmd --head  --request GET www.google.com |grep "HTTP/"))
if [[ $(echo $netStatus | grep "Moved") ]]; then #Moved -> redirected to login portal
	netStatus=""
fi

if [[ "$netStatus" ]]; then
	echo "Connected to $(iwconfig $wifiif | sed -n 's/.*Access Point: \([0-9\:A-F]\{17\}\).*/\1/p')"
	syncTime
	$onlineCommand> /dev/null 2>&1 &
else
	echo "Disconnected."
	starttime=$(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s)
fi
echo "-------------------------------------------------------------------------------"
echo "$(date "+%Y-%m-%d - %H:%M:%S") - Starting script"
echo "-------------------------------------------------------------------------------"

# -------------------------------- Start Loop ---------------------------------------

while true ; do
	currenttime=$(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s)
	totaltime=$(($currenttime - $starttime))
#-------------------------------- Check Connection ----------------------------------
	netStatus=""
	connRetryTemp=$(expr $connRetry + 1 )
	while [ "$netStatus" = "" -a "$connRetryTemp" -ge 1 ] ;do
		netStatus=$(echo $(curl $curlCmd --head www.google.com |grep "HTTP/"))
			
		if [[ $(echo $netStatus | grep "Moved") ]]; then #Moved -> redirected to login portal
			echo "Redirected to login portal"
			netStatus=""
			connRetryTemp=0
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
				else
					serverLoad="Offline"
				fi
			elif [ $serverLoad -gt $vpnMload ]; then
				echo -n "VPN Load over 75% ($serverLoad%), connecting to new server: "
				vpnConnect
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
		echo -n " $connectionVer|T:$(printf "%02d" $(($(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s) - $currenttime)))|$(date -d "1970-01-01 + $totaltime seconds" "+%H:%M:%S")|U/D ${arrOUT[5]} ${arrOUT[6]}"
		echo -n "|$serverName $serverLoad|CPU$cpuuse" $(cat /sys/class/thermal/thermal_zone0/temp | sed 's/\(.\)..$/.\1°C/')"|"
		echo -e $netStatus
	else

# -------------------------------------- OFFLINE ------------------------------------

		echo " T:$(printf "%02d" $(($(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s) - $currenttime)))|$(date -d "1970-01-01 + $totaltime seconds" "+%H:%M:%S") - Offline - $(date "+%d-%m-%y - %H:%M:%S")"
		mpg321 -q $SCRIPT_DIR/alarm.mp3
		echo "-------------------------------------------------------------------------------"
		forceSynctime=1
		vpnDisconnect

	#Login into MEO-WiFi
		echo "Login to MEO WiFi...."
		connect=$(connectMeoWiFiv1)
		if [ "$connect" == 'null' ] || [ "$connect" == '"Já se encontra logado"' ] ; then
			echo "Successfully connected to MEO WiFi"
			continue
		#Start VPN
			if $vpn ; then
				echo -n "Connecting to ProtonVPN: "
				vpnConnect
			fi
			XDG_RUNTIME_DIR=/run/user/$(id -u) notify-send  "Successfully connected to MEO WiFi"
			$onlineCommand> /dev/null 2>&1 &					
		elif [ "$connect" == '"OUT OF REACH"' ] ; then
			echo -e "Someting went wrong. \nError code: $connect"
			echo "Trying v2 login..."
			vpnDisconnect
			connectMeoWiFiv2
			connectionVer='v2'
			continue
		elif [ "$connect" == '"De momento não é possível concretizar o seu pedido. Por favor, tente mais tarde."' ] || [ "$connect" == '"The service is unavailable."' ] ; then
			echo -e "Someting went wrong, retrying in 5s...\nError code: $connect"
			sleep 5
			continue
		else
			echo -e "Someting went wrong\nError code: $connect"
			echo "Disconecting from $(iwconfig $wifiif | sed -n 's/.*Access Point: \([0-9\:A-F]\{17\}\).*/\1/p')"
		# Get BSSID List.		
			echo $rPasswd | sudo -S nmcli --fields SSID,BSSID device wifi list --rescan auto | grep "MEO-WiFi" > $HOME/.config/meoConnect/${0##*/}.lst
			sed -i 's/MEO-WiFi//g' $HOME/.config/meoConnect/${0##*/}.lst
			sed -i 's/ //g' $HOME/.config/meoConnect/${0##*/}.lst
		# Connecting to BSSID list.	
			bssid=""
			while read p; do
				echo $rPasswd | sudo -S ifconfig $wifiif down > /dev/null 2>&1
				sleep 2
				echo "Connecting to $p"
				echo $rPasswd | sudo -S nmcli connection modify $wifiap 802-11-wireless.bssid "$p"
				sleep 2
				echo $rPasswd | sudo -S ifconfig $wifiif up > /dev/null 2>&1
				sleep 2
				nmcli connection up "$wifiap" ifname "$wifiif" > /dev/null 2>&1
				bssid=$(iwconfig $wifiif | sed -n 's/.*Access Point: \([0-9\:A-F]\{17\}\).*/\1/p')
				ip=$(ip addr show $wifiif | awk '/inet / {print $2}')
				echo "ip: $ip"
				if [[ "$ip" != "" ]] ; then
					break
				fi
			done <$HOME/.config/meoConnect/${0##*/}.lst	
			forceSynctime=1
			echo "Connected to $(iwconfig $wifiif | sed -n 's/.*Access Point: \([0-9\:A-F]\{17\}\).*/\1/p')"
			continue
		fi
		echo "-------------------------------------------------------------------------------"
	fi

# ----------------------------------- Pause script ----------------------------------

	skipTime=$(($recheckTime - ($(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s) - $currenttime + 1)))
	skip=""
	
	while [ "$skip" != "f" -a "$skipTime" -ge 0 ] ;do 
		echo -n -e ">>>>>>>> T-$skipTime""s , \033[4;1mF\033[0morce , \033[4;1mV\033[0mPN , \033[4;1mE\033[0mdit , \033[4;1mC\033[0monfig , \033[4;1mS\033[0mtatus , \033[4;1mR\033[0meload , \033[4;1mQ\033[0muit <<<<<<<<"
		read -rsn1 -t 1 skip
		echo -e -n "\r\033[K"
		
		if [[ $skip = "" ]]; then
			skipTime=$(expr $skipTime - 1 )
		elif [[ $skip = "v" ]]; then
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
		elif [[ $skip = "e" ]]; then
			echo "Running script editor..."
			$( nohup $editor $(dirname "$0")/meoConnect.sh $confFile> /dev/null 2>&1 & )
		elif [[ $skip = "c" ]]; then
			editSettings
# -------------------------------------- TESTE --------------------------------------
		elif [[ $skip = "t" ]]; then
			echo "------ TESTE -------"
			





			echo "------ TESTE -------"
# -------------------------------------- TESTE --------------------------------------
		elif [[ $skip = "s" ]]; then
			echo "-------------------------------------------------------------------------------"
			json=$(curl $curlCmd "https://servicoswifi.apps.meo.pt/HotspotConnection.svc/GetState?mobile=false")
			echo "Corrent connection:"
			json=$(echo $json | jq '.Consumption')
			echo "DownstreamMB: $(echo $json | jq '.DownstreamMB')"
			echo "UpstreamMB: $(echo $json | jq '.UpstreamMB')"
			syncTime
			echo "-------------------------------------------------------------------------------"
		elif [[ $skip = "q" ]]; then
			exit
		elif [[ $skip = "r" ]]; then
			echo "Reloading script"
			sleep 1
			mpg321 -q $SCRIPT_DIR/alarm.mp3
			exec meoConnect.sh
			exit
		fi	
	done
done
