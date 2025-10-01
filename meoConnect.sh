#!/bin/bash

version='0.675'

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

connectMeoWiFi () {
		mpg321 -q $OnlineFile > /dev/null 2>&1 &
		if [ $(iwconfig $wifiif | sed -n 's/.*Access Point: \([0-9\:A-F]\{17\}\).*/\1/p') ] ; then
			echo "Connecting to          : $(iwconfig $wifiif | sed -n 's/.*Access Point: \([0-9\:A-F]\{17\}\).*/\1/p')"
			nmcli connection up "$wifiap" ifname "$wifiif" > /dev/null 2>&1

			echo -n "Login to MEO WiFi      : "
			connect=$(connectMeoWiFiv2)
			echo "$connect"
		else
			connect="NO Session Id Found..."
		fi
		
		if [ "$connect" == "NO Session Id Found..." ] ; then

		# Get BSSID List.
			echo $rPasswd | sudo -S ifconfig $wifiif up > /dev/null 2>&1
			echo -n "Scanning for MEO WiFi networks: " 
			echo $rPasswd | sudo -S nmcli --fields SSID,BSSID device wifi list ifname $wifiif --rescan yes | grep "MEO-WiFi" > $HOME/.config/meoConnect/${0##*/}.lst
			sed -i 's/MEO-WiFi//g' $HOME/.config/meoConnect/${0##*/}.lst
			sed -i 's/ //g' $HOME/.config/meoConnect/${0##*/}.lst
			APCount=$(echo -e " $(wc -l < $HOME/.config/meoConnect/${0##*/}.lst)")
			echo -e " $APCount APs found. \033[1;92mDone.\033[0m"
			cat -b $HOME/.config/meoConnect/${0##*/}.lst
			if [ $APCount != 0 ] ; then

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
			else
				echo " no aps found sleeping 30s."
					sleep 30
			
			fi
			forceSynctime=1
			remLine=false
			connectMeoWiFi

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
	
	
	
	if [ "$sessionId" != "null" -a "$sessionId" != "" ]; then
	# Construct the URL for session login
		url="https://meowifi.meo.pt/wifim-scl/service/${sessionId}/session-login"
	# Construct the login request body
		login_body="{\"userName\":\"$user\",\"password\":\"$passwd\",\"ipAddress\":\"$ip\",\"sessionId\":\"$sessionId\",\"loginType\":\"login\"}"
	# Send a POST request for login
		response=$(curl $curlCmd -X POST -H "Content-Type: application/json" -d "$login_body" "$url")
		
		echo -e "\033[1;92mConnected.\033[0m"

	else
		echo -e "NO Session Id Found..."
	fi
}

editSettings () {

# User Password
	echo -n "Please enter Root password ($rPasswd):"
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
		recheckTime=60
	
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
	echo "    : one value is sent to the scrip"
	echo "    : 1-BSSID "
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

# Text Editor
editor='$editor'

# curl command
curlCmd='-s --interface $wifiif --connect-timeout 20 --max-time 20 -H "Cache-Control: no-cache, no-store, must-revalidate, Pragma: no-cache, Expires: 0"'

# Number of retries
connRetry='$connRetry'

EOF
}

setDNS () {
	
echo $rPasswd | sudo -S cp -f $dnsFile /etc/resolv.conf  > /dev/null 2>&1
}

syncTime () {
	
	checkUpdate
	echo -n "Getting Connection Time:"
	meoTime=""
	json=""	
	remLine=false

	ip=$(ip addr show $wifiif | awk '/inet / {print $2}')
	ip=${ip%/*}	
	url="https://meowifi.meo.pt/wifim-scl/service/session-status"
	body="{\"ipAddress\":\"$ip\"}"

	# Send a POST request and parse the session ID from the JSON response
	sessionId=$(curl $curlCmd -X POST -H "Content-Type: application/json" -d "$body" "$url")
	sessionInfo=$(echo $sessionId | jq '.sessionInfo' )
	
	meoTime=$(echo $sessionInfo | jq -r '.sessionInitialDate')
	if [ "$meoTime" != "null" ]; then
		meoTime="${meoTime:11:8}"
		starttime=$(date -d "$meoTime Z" +%s)
		currenttime=$(date --date """$(date "+%H:%M:%S")""" +%s)
		totaltime=$(($currenttime - $starttime))
		echo -e "\033[0m $(date -d "1970-01-01 + $totaltime seconds" "+%H:%M:%S")"
		XDG_RUNTIME_DIR=/run/user/$(id -u) notify-send  "Successfully connected to MEO WiFi"		
		echo -n -e "Running OLCmd          : \033[0;96m"
		echo $($OLCmd $(iwconfig $wifiif | sed -n 's/.*Access Point: \([0-9\:A-F]\{17\}\).*/\1/p'))
		echo -e "\033[0m                       : \033[1;92mDone.\033[0m"
		echo "-----------------------:-------------------------------------------------------"
	else
		starttime=$(date --date """$(date "+%H:%M:%S")""" +%s)
		echo -e "\033[1;91m Fail.\033[0m"
		echo "-----------------------:-------------------------------------------------------"
	fi
	
	}

checkUpdate () {

	echo -n "Checking for updates   : "
	gitVer=$(timeout --preserve-status -k 5 15 curl -H "Cache-Control: no-cache, no-store, must-revalidate, Pragma: no-cache, Expires: 0" https://raw.githubusercontent.com/ClawsPT/meoConnect/main/meoConnect.sh -s -r 13-28 | grep "version")
	if [ "$gitVer" ] ; then
		if [ "$gitVer" == "version='$version'" ] ; then
			echo -e "\033[1;92mUp-to-date.\033[0m ($gitVer)"
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
			sleep 2
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
for name in geany mpg321 vnstat curl jq awk notify-send
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
#mpg321 -q $OnlineFile > /dev/null 2>&1 &
echo -n "Checking Connection    : "
netStatus=""
netStatus=$(echo $(curl $curlCmd --head  --request GET www.google.com |grep "HTTP/"))
if [[ $(echo $netStatus | grep "Moved") ]]; then #Moved -> redirected to login portal
	netStatus=""
fi

if [[ "$netStatus" ]]; then
	echo -e "\033[1;92mConnected to\033[0m $(iwconfig $wifiif | sed -n 's/.*Access Point: \([0-9\:A-F]\{17\}\).*/\1/p')"
	syncTime
else
	echo -e "\033[1;91mDisconnected.\033[0m"
	starttime=$(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s)
fi
echo    "Starting script        : $(date "+%Y-%m-%d - %H:%M:%S")"
echo -e "-----------------------:-------------------------------------------------------"

}

# -------------------------------- Scrip Start --------------------------------------

clear
echo "-------------------------------------------------------------------------------"
echo -e "|                   MEO Wifi AutoConnect v$version                   By: Claws\033[1;91mP\033[1;92mT\033[0m |"
echo "-------------------------------------------------------------------------------"

looptime=$(date --date """$(date "+%H:%M:%S")""" +%s)
startUp

# -------------------------------- Start Loop ---------------------------------------

while true ; do
	currenttime=$(date --date """$(date "+%H:%M:%S")""" +%s)
	totaltime=$(($currenttime - $starttime))
	if [ $totaltime -lt 0 ] ; then 
		totaltime=$(($totaltime + 86400))
	fi	
#-------------------------------- Check Connection ----------------------------------
	netStatus=""

	# If over 2h force Reconnect else check connection
	
	if [ "$totaltime" -lt 7200 ] ; then

		connRetryTemp=$(expr $connRetry + 1 )
		while [ "$netStatus" = "" -a "$connRetryTemp" -ge 1 ] ;do
			netStatus=$(echo $(curl $curlCmd --head www.google.com | grep "HTTP/"))
			netStatus=$(printf "$netStatus" | sed 's/\r//g' | sed 's/HTTP\/1.1 //g' | sed 's/HTTP\/1.0 //g')
			if [[ $(echo $netStatus | grep "Moved") ]] || [[ $(echo $netStatus | grep "Found") ]]; then #Moved -> redirected to login portal
				echo "-----------------------:-------------------------------------------------------"
				echo -e " \033[1;91m------ OFFLINE ------\033[0m | At: $(date "+%H:%M:%S") | \033[1;92mRedirected to login portal\033[0m - $netStatus"
				echo "-----------------------:-------------------------------------------------------"
				mpg321 $OfflineFile > /dev/null 2>&1
				echo -e -n "Login to MEO WiFi      : "
				connectMeoWiFiv2
				echo -e "Session ID             : $(echo $sessionId)" # | jq -r '.sessionId')"
				echo -e "Offline Time           : $(printf "%02d" $(($(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s) - $looptime )))s"
				starttime=$(date --date """$(date "+%H:%M:%S")""" +%s)
				forceSynctime=1
				remLine=false
				netStatus=""
				continue
			fi
			connRetryTemp=$(expr $connRetryTemp - 1 )
		done
		
		else                                          : 
			echo -e " -----> 2h reached               : \033[1;92mreconnecting...\033[0m"
			sleep 2
	fi
# ---------------------------------- ONLINE -----------------------------------------
	
	if [[ "$netStatus" ]]; then

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

		if [ $totaltime -lt 0 ] ; then 
			totaltime=$(($totaltime + 86400))
		fi	
	
		if [ $totaltime -gt 6900 ] ; then
			CTime="\033[1;91m$(date -d "1970-01-01 + $totaltime seconds" "+%H:%M:%S")\033[0m"
		elif [ $totaltime -gt 6300 ] ; then
			CTime="\033[1;93m$(date -d "1970-01-01 + $totaltime seconds" "+%H:%M:%S")\033[0m"
		else
			CTime="\033[1;92m$(date -d "1970-01-01 + $totaltime seconds" "+%H:%M:%S")\033[0m"
		fi
		
		echo -n -e " T:$(printf "%02d" $(($(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s) - $looptime ))) | $CTime |Dn/Up: ${arrOUT[1]}${arrOUT[2]} / ${arrOUT[3]}${arrOUT[4]}"
		echo -n " | CPU$cpuuse" $(cat /sys/class/thermal/thermal_zone0/temp | sed 's/\(.\)..$/.\1°C/')" | "
		echo $netStatus	
	else

# -------------------------------------- OFFLINE ------------------------------------
		
		echo "-----------------------:-------------------------------------------------------"
		echo -e " \033[1;91m------ OFFLINE ------\033[0m : At: $(date "+%H:%M:%S") | ConnectionTime: $(date -d "1970-01-01 + $totaltime seconds" "+%H:%M:%S")"
		#mpg321 $OfflineFile > /dev/null 2>&1
		echo "-----------------------:-------------------------------------------------------"
		forceSynctime=1
		#Login into MEO-WiFi
		connectMeoWiFi
		echo -e "Session ID             : $(echo $sessionId | jq -r '.sessionId')"
		echo -e "Offline Time           : $(printf "%02d" $(($(date --date """$(date "+%Y-%m-%d %H:%M:%S")""" +%s) - $looptime )))s"
		starttime=$(date --date """$(date "+%H:%M:%S")""" +%s)
		
		continue
	fi

# ----------------------------------- Loop script ----------------------------------

	TMoveTzero=$(($EPOCHSECONDS - $starttime))
	
	if [ $TMoveTzero -lt 0 ] ; then 
		TMoveTzero=$(($TMoveTzero + 86400))
	fi	
	
	while [ "$TMoveTzero" -ge 59 ] ; do
		
		TMoveTzero=$(expr $TMoveTzero - 60)
			
	done

	skipTime=$(($recheckTime - $TMoveTzero - 1))
	skip=""
	
	while [ "$skip" != "f" -a "$skipTime" -ge 0 ] ;do
		linkQuality=$(iwconfig $wifiif | awk -F= '/Quality/ {print $2}' | awk -F/ '{print $1}')
	
		echo -e -n ">>>>   T-$skipTime""s  S:$linkQuality%   \033[4;1mF\033[0morce   c\033[4;1mH\033[0mange AP   \033[4;1mC\033[0monfig    \033[4;1mS\033[0mtatus   \033[4;1mR\033[0meload   \033[4;1mQ\033[0muit <<<"
		
		read -rsn1 -t 1 skip
		echo -e -n "\r\033[K"	
		if [[ $skip = "" ]]; then
			skipTime=$(expr $skipTime - 1 )

		elif [[ $skip = "h" ]]; then

			# Get BSSID List.
				echo "-----------------------:-------------------------------------------------------"
				echo -n "Scanning MEO-WiFi networks: " 				
				echo $rPasswd | sudo -S ifconfig $wifiif up > /dev/null 2>&1
				echo $rPasswd | sudo -S nmcli --fields SSID,BSSID,CHAN,BARS,SIGNAL device wifi list ifname $wifiif --rescan yes | grep "MEO-WiFi" | sort > $HOME/.config/meoConnect/${0##*/}.lst
				#sed -i 's/MEO-WiFi             //g' $HOME/.config/meoConnect/${0##*/}.lst
				#sed -i 's/  //g' $HOME/.config/meoConnect/${0##*/}.lst
				echo -e "\033[1;92mDone.\033[0m $(wc -l < $HOME/.config/meoConnect/${0##*/}.lst) APs found."
	
			# Connecting to BSSID list.
				echo "     # |                 BSSID                     |Chan| Signal   "
				cat -b $HOME/.config/meoConnect/${0##*/}.lst
				echo ""
				read -r -t 25 -p "Connect to: " lineNumber
				if  [[ $lineNumber != "" ]]; then 
					bssid=$(sed -n "$lineNumber"p $HOME/.config/meoConnect/${0##*/}.lst)
					bssid=$(echo $bssid | sed -n 's/.*MEO-WiFi \([0-9\:A-F]\{17\}\).*/\1/p')
					bssid=$(echo $bssid | cut -c1-17)
					echo -n "Setting new BSSID      : "					
					echo $rPasswd | sudo -S ifconfig $wifiif down > /dev/null 2>&1
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
				fi

		elif [[ $skip = "c" ]]; then
			editSettings
# ----------------------------------------------- TESTE -----------------------------------------
		elif [[ $skip = "t" ]]; then
			echo "-----------------------:------- TESTE -----------------------------------------"
			echo ""
		
		
		
				echo $starttime
				starttime=$(($starttime - 7200))
 
 
 
			echo ""
			echo "-----------------------:------- TESTE -----------------------------------------"
			echo ""
			skip="f"
# ----------------------------------------------- TESTE -----------------------------------------
		
		
		elif [[ $skip = "u" ]]; then
			echo -ne '\e[1A\e[K'
			checkUpdate
			echo "-----------------------:-------------------------------------------------------"
			echo ""
			skip="f"
		elif [[ $skip = "s" ]]; then
			echo "-----------------------:-------------------------------------------------------"
		
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
				starttime=$(date -d "$meoTime Z" +%s)
				currenttime=$(date --date """$(date "+%H:%M:%S")""" +%s)
				totaltime=$(($currenttime - $starttime))
				if [ $totaltime -lt 0 ] ; then 
					totaltime=$(($totaltime + 86400))
				fi
				echo ""
				echo "    Meo:"
				echo -e "        SessionID      : $(echo $sessionId | jq -r '.sessionId')"
				echo -e "        Connection time: $(date -d "1970-01-01 + $totaltime seconds" "+%H:%M:%S") ( $totaltime )"			
			else
				echo ""
				echo "    Meo:"
				echo -e "        Connection time: Fail"
			fi
			
			echo "    VnStat (today):"
			echo "        Downstream     : ${arrOUT[1]}${arrOUT[2]}"
			echo "        Upstream       : ${arrOUT[3]}${arrOUT[4]}"
			echo "        Total          : ${arrOUT[5]}${arrOUT[6]}"
			echo "        Speed          : ${arrOUT[7]}${arrOUT[8]}"
			echo ""
			checkUpdate
			#syncTime
			echo "-----------------------:-------------------------------------------------------"
			echo ""
			skip="f"
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
	looptime=$(date --date """$(date "+%H:%M:%S")""" +%s)
	remLine=true
done
