#!/bin/bash

version='0.352'

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

ip=$(ip addr show wlan1 | awk '/inet / {print $2}')
ip=${ip%/*}	

echo $(python3 -c "$PYCMD" -u $ip -p $passwd)	
	
}

vpnConnect () {
	if [[ $(ifconfig | grep "proton") || $(ifconfig | grep "ipv6leakintrf") ]]; then
		foo=$(timeout --preserve-status -k 5 30 protonvpn-cli d)
	fi
	vpnConn=$(timeout --preserve-status -k 5 45 protonvpn-cli connect --cc NL --protocol udp | grep "Successfully connected")  #timeout --preserve-status 20 
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
	if [[ $(ifconfig | grep proton) ]] ; then
		echo -n "Disconnecting ProtonVPN: "
		vpnDisConn=$(timeout --preserve-status -k 5 30 protonvpn-cli d | grep "Successfully disconnected")  #timeout --preserve-status 20 
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

connectMeoWiFi () {

	ip=$(ip addr show wlan1 | awk '/inet / {print $2}')
	ip=${ip%/*}								
	encPwd=$(encryptPasswd)
	connRetry=3
	json=""
	
	while [ "$json" = "" -a "$connRetry" -ge 1 ] ;do
		sleep 1
		json=$(curl $curlCmd "https://servicoswifi.apps.meo.pt/HotspotConnection.svc/Login?username="$user"&password="$encPwd"&navigatorLang=pt&callback=foo")
		connRetry=$(expr $connRetry - 1 )
	done
	
	json=${json#????}
	json=${json%??}
	error=$(echo $json | jq '.error')
	if [[ "$error" ]]; then
		echo "$error"
	else
		echo "Connection timeout. ($connRetry) $json"
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
	echo -n "Please enter WiFi Connection Name ($wifiap):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		wifiap=$sTemp
	fi
	
# Wireless device name
	echo -n "Please enter Wireless device name ($wifiif):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		wifiif=$sTemp
	fi
	
# Meo WiFi username
	echo -n "Please enter Meo WiFi username ($user):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		user=$sTemp
	fi
	
# Meo WiFi Password
	echo -n "Please enter Meo WiFi Password ($passwd):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		passwd=$sTemp
	fi
	
# Time in seconds between network checks
	echo -n "Please enter  Time in seconds between network checks ($recheckTime):"
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
	echo -n "Please enter VPN max load ($vpnMload):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		vpnMload=$sTemp
	fi
	
# Text Editor
	editor='geany'

	echo -n "Save Configuration (y/n):"
	read -r sTemp
	if [ "$sTemp" ] ; then
		if [ $sTemp = "y" ] ; then
			saveSettings
		fi
	fi
}

saveSettings () {

echo "Saving Settings into $HOME/.config/meoConnect/meoConnect.conf"	
FILE="$HOME/.config/meoConnect/meoConnect.conf"
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
curlCmd="-s --interface wlan1 --connect-timeout 20 --max-time 10 -H 'Cache-Control: no-cache, no-store'"

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

clear

echo "-------------------------------------------------------------------------------"
echo "|                         MEO Wifi AutoConnect v$version                         |"
echo "-------------------------------------------------------------------------------"

echo "Loading Configuration  : Done."
source $HOME/.config/meoConnect/meoConnect.conf
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo -n "Checking Dependencies  : "
for name in protonvpn-cli geany mpg321 vnstat curl jq awk notify-send
	do
	  [[ $(which $name 2>/dev/null) ]] || { echo -en "\n$name needs to be installed. Use 'sudo apt-get install $name'";deps=1; }
	done
	[[ $deps -ne 1 ]] && echo "Done." || { echo -en "\nInstall the above and rerun this script\n";exit 1; }

if [ ! -f $HOME/.config/meoConnect/meoConnect.conf ]; then
    echo "Configuration File not found..."
    editSettings
	echo "Reloading script"
	sleep 1
	exec $SCRIPT_DIR/meoConnect.sh 
	mpg321 -q $SCRIPT_DIR/alarm.mp3
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
netStatus=$(echo $(curl $curlCmd --head  --request GET www.google.com |grep "HTTP/"))
	
if [[ $(echo $netStatus | grep "Moved") ]]; then #Moved -> redirected to login portal
	netStatus=""
fi
	
if [[ "$netStatus" ]]; then
	echo "Connected."
	echo -n "Getting Connection Time: "
	meoTime=""	
	while [[ ! "$meoTime" ]] ;do	 
		json=$(curl --interface $wifiif $curlCmd "https://servicoswifi.apps.meo.pt/HotspotConnection.svc/GetState?callback=foo&mobile=false&pagePath=foo")
		json=${json#????}
		json=${json%??}
		json=$(echo $json | jq '.Consumption')
		meoTime=$(echo $json | jq '.Time')
		meoTime=${meoTime#?}
		meoTime=${meoTime%?}
		echo "$meoTime:00"
	done
	meoTime="$meoTime:00"
	meoTime=$(date -d "1970-01-01 $meoTime Z" +%s)
	currenttime=$(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s)				
	starttime=$(($currenttime - $meoTime))
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

	netStatus=$(echo $(curl $curlCmd --head www.google.com |grep "HTTP/"))
		
	if [[ $(echo $netStatus | grep "Moved") ]]; then #Moved -> redirected to login portal
		echo "Redirected to login portal"
		netStatus=""
	fi
	
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
			serverName=""
			serverLoad="VPN Offline"
		fi
		
	#Get traffic and cpu
		cpuuse=$(cat <(grep 'cpu ' /proc/stat) <(sleep 1 && grep 'cpu ' /proc/stat) | awk -v RS="" '{printf "%6.2f%\n", ($13-$2+$15-$4)*100/($13-$2+$15-$4+$16-$5)}')
		IN=$(vnstat -d | (tail -n3))
		INR=${IN//estimated}
		arrOUT=(${INR//|/ })
		echo -n " T:$(printf "%02d" $(($(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s) - $currenttime)))|$(date -d "1970-01-01 + $totaltime seconds" "+%H:%M:%S")|Up/Dn ${arrOUT[5]} ${arrOUT[6]}"
		echo -n "|$serverName $serverLoad|CPU $cpuuse|"
		echo -e $netStatus	
	else

# -------------------------------------- OFFLINE ------------------------------------

		echo " T:$(printf "%02d" $(($(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s) - $currenttime)))|$(date -d "1970-01-01 + $totaltime seconds" "+%H:%M:%S") - Offline - $(date "+%d-%m-%y - %H:%M:%S")"
		mpg321 -q $SCRIPT_DIR/alarm.mp3
		echo "-------------------------------------------------------------------------------"
		
#Disconnect Proton VPN & Reconnect to MeoWiFi	
		#echo "Reconnecting MEO WiFi"	
		#nmcli connection up "$wifiap" ifname "$wifiif" > /dev/null		
		vpnDisconnect
		
#Login into MEO-WiFi
		echo "Login to MEO WiFi...."
		sleep 5
		connect=$(connectMeoWiFi)
		if [ "$connect" == 'null' ] || [ "$connect" == '"Já se encontra logado"' ] ; then
			echo "Successfully connected to MEO WiFi"
			echo -n "Cheking connection time: "
			meoTime=""	
			while [[ ! "$meoTime" ]] ;do	 
				json=$(curl --interface $wifiif $curlCmd "https://servicoswifi.apps.meo.pt/HotspotConnection.svc/GetState?callback=foo&mobile=false&pagePath=foo")
				json=${json#????}
				json=${json%??}
				json=$(echo $json | jq '.Consumption')
				meoTime=$(echo $json | jq '.Time')
				meoTime=${meoTime#?}
				meoTime=${meoTime%?}
			done
			meoTime="$meoTime:00"
			echo "$meoTime"
			meoTime=$(date -d "1970-01-01 $meoTime Z" +%s)
			currenttime=$(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s)				
			starttime=$(($currenttime - $meoTime))			
			sleep 2
		
#Start VPN 			
			if $vpn ; then
				echo -n "Connecting to ProtonVPN: "
				sleep 2
				vpnConnect
			fi
			XDG_RUNTIME_DIR=/run/user/$(id -u) notify-send  "Successfully connected to MEO WiFi"
			starttime=$(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s)
			
		elif [ "$connect" == '"OUT OF REACH"' ] ; then
			echo -e "Someting went wrong, retrying in 60s...\nError code: $connect"
			vpnDisconnect
			nmcli connection up "$wifiap" ifname "$wifiif" > /dev/null
		elif [ "$connect" == '"De momento não é possível concretizar o seu pedido. Por favor, tente mais tarde."' ] ; then
			echo -e "Someting went wrong, retrying in 60s...\nError code: $connect"
			sleep 2
			continue
		else
			echo -e "Someting went wrong, retrying ...\nError code: $connect"
#Stoping ProtonVPN and reconnecting wifi
			vpnDisconnect
			echo "Reconnecting MEO WiFi"
			nmcli connection up "$wifiap" ifname "$wifiif" > /dev/null
			sleep 5			
			continue
		fi
		echo "-------------------------------------------------------------------------------"
	fi

#Pause script

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
			$( nohup $editor $(dirname "$0")/meoConnect.sh $HOME/.config/meoConnect/meoConnect.conf> /dev/null 2>&1 & )
		elif [[ $skip = "c" ]]; then
			editSettings
		
#Teste
		elif [[ $skip = "t" ]]; then
			echo "------ TESTE -------"
			
			
		
			vpnConnect
			
			
			
		elif [[ $skip = "s" ]]; then		
			echo "-------------------------------------------------------------------------------"		
			json=$(curl --interface $wifiif $curlCmd "https://servicoswifi.apps.meo.pt/HotspotConnection.svc/GetState?callback=foo&mobile=false&pagePath=foo")
			json=${json#????}
			json=${json%??}
			echo "Corrent connection:"
			json=$(echo $json | jq '.Consumption')
			echo "DownstreamMB: $(echo $json | jq '.DownstreamMB')"
			echo "UpstreamMB: $(echo $json | jq '.UpstreamMB')"
			echo "Time: $(echo $json | jq '.Time')"
			echo "Updating clock"
			echo "-------------------------------------------------------------------------------"
			meoTime=$(echo $json | jq '.Time')
			meoTime=${meoTime#?}
			meoTime=${meoTime%?}":00"
			meoTime=$(date -d "1970-01-01 $meoTime Z" +%s)
			currenttime=$(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s)			
			starttime=$(expr $currenttime - $meoTime)
		
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
