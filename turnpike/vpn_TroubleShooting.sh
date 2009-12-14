#!/bin/bash
#
# vpn_TroubleShooting.sh is a tool for tracing the VPN's problem,
# and collect the log and system status into a single tar file.
#
# Authors:
#    Libin       bili@novell.com or libin.charles@gmail.com
#    John Shi    jshi@novell.com
#
# Change Log: 
#
# $Log: vpn_TroubleShooting.sh,v $
# Revision 1.12  2007/12/04 05:46:34  libin
# Clear the SPD and SAD, and save ipcfg file
#
# Revision 1.10  2007/09/17 02:26:05  libin
# Get the ip address by ifconfig
#
# Revision 1.9  2007/09/14 10:21:32  libin
# Log user's select menu for connect VPN
#
# Revision 1.8  2007/09/14 06:57:03  libin
# Capture all network card not just only the first on
#
# Revision 1.7  2007/08/30 08:48:19  libin
# User can determine when disconnect
#
# Revision 1.6  2007/08/22 10:32:22  libin
# Fix bug when the nvpn's list is null
#
# Revision 1.5  2007/08/22 07:43:23  libin
# Add the nortelplugins's checking
#
# Revision 1.4  2007/08/22 03:20:33  libin
# Add root user's check
#
# Revision 1.3  2007/08/22 02:40:54  libin
# Change the singal's warning.
#
# Revision 1.2  2007/08/21 11:04:57  libin
# finish the first version
#
#

# global variant
MYDATE=`date +%m%d-%H%M%S`
TROUBLESHOOTING=vpn_TroubleShooting
TAR_FILE=${TROUBLESHOOTING}${MYDATE}.tar.gz
TEMP_PATH=/tmp
LOG_PATH=$TEMP_PATH/$TROUBLESHOOTING
TURNPIKE_PATH=~/.turnpike
TURNPIKE_LOG=$TURNPIKE_PATH/log.txt
RACOON_PATH=/etc/racoon/
RACOON_LOG=/var/log/messages
VPN_CMD=/usr/bin/nvpn
SYSLOGD=/etc/init.d/syslog
TURNPIKE=turnpike
IPSEC_TOOLS=novell-ipsec-tools
NORTEL_PLUGINS=novell-nortelplugins
RPM_CMD=rpm
ISSUE=/etc/issue
SYS_VERSION=/proc/version
RACOOND=/usr/sbin/racoon
RACOON_CONF=${RACOON_PATH}racoon.conf
NVPN_LOG=$LOG_PATH/nvpn.log
TCPDUMP=/usr/sbin/tcpdump
CAPTURE_PKG=$LOG_PATH/$TROUBLESHOOTING.cap
FAILED='[01;31mFAILED[0m'
OK='[01;32mOK[0m'
TAB='\t'
PROCESS_LOG=$LOG_PATH/process.log
IFCFG=/sbin/ifconfig
SETKEY=/usr/sbin/setkey
IPCFG=/var/tmp/ipcfg
DNSCONF=/etc/resolv.conf

NEED_PACKAGE=0

if [ $EUID -eq 0 ]; then
	echo -e "Note: Suggest don't use the root user! Cause some configuration file is in the ~/."
	echo -en "Do you want run it? (y/N)"
	read -n 1 FLAG
	if [ "$FLAG" != "y" -a "$FLAG" != "\n" ]; then
		exit 0
	fi
fi

echo -e "\nGet the sudo permission ..."
if sudo true
then
	echo -e "$OK!"
else
	echo -e "$FAILED!"
	exit 1
fi

# mkdir for save the log and status of system
if [ -d $LOG_PATH ]; then 
	echo -en "The $LOG_PATH already exist! Delete it ..."
	if sudo rm -rf $LOG_PATH ; then
		echo -e "$TAB $OK!"
	else
		echo -e "$TAB $FAILED!"
	fi
fi

if [ -e "$TAR_FILE" ]; then
	echo -en "The $TAR_FILE already exist! Delete it ..."
	if sudo rm -f $TAR_FILE ; then
		echo -e "$TAB $OK!"
	else
		echo -e "$TAB $FAILED!"
	fi
fi

echo -en "Create the $LOG_PATH ..."
if mkdir $LOG_PATH ; then
	echo -e "$TAB $OK!"
else
	echo -e "$TAB $FAILED!"
fi

echo -e "Check the package info of turnpike, novell-ipsec-tools, and novell-nortelplugins ..."
if $RPM_CMD -qisl $TURNPIKE > $LOG_PATH/$TURNPIKE.pkginfo
then
	echo -e " Get $TURNPIKE's info is $OK!"
	for file in `$RPM_CMD -ql $TURNPIKE`
       	do
	       	[ -e $file ] || echo "No such file: $file in $TURNPIKE, please reinstall the $TURNPIKE" | tee -a $PROCESS_LOG
       	done
else
	echo -e " ************** Please install the $TURNPIKE package! **************"
	NEED_PACKAGE=1
fi

if $RPM_CMD -qisl $IPSEC_TOOLS > $LOG_PATH/$IPSEC_TOOLS.pkginfo
then
	echo -e " Get $IPSEC_TOOLS's info is $OK!"
	for file in `$RPM_CMD -ql $IPSEC_TOOLS`
       	do
	       	[ -e $file ] || echo "No such file: $file in $IPSEC_TOOLS, please reinstall the $IPSEC_TOOLS" | tee -a $PROCESS_LOG
       	done
else
	echo -e " ************** Please install the $IPSEC_TOOLS package! **************"
	NEED_PACKAGE=1
fi

if $RPM_CMD -qisl $NORTEL_PLUGINS > $LOG_PATH/$NORTEL_PLUGINS.pkginfo
then
	echo -e " Get $NORTEL_PLUGINS's info is $OK!"
	for file in `$RPM_CMD -ql $NORTEL_PLUGINS`
       	do
	       	[ -e $file ] || echo "No such file: $file in $NORTEL_PLUGINS, please reinstall the $NORTEL_PLUGINS" | tee -a $PROCESS_LOG
       	done
else
	echo -e " ************** Please install the $NORTEL_PLUGINS package! **************"
	NEED_PACKAGE=1
fi

if [ ! -e $TCPDUMP ]; then
	echo -e " ************** Please install the tcpdump package! **************"
	NEED_PACKAGE=1
fi

if [ $NEED_PACKAGE -eq 1 ]; then
	exit 1
fi

echo -e "Get system info ..."
if [ -e $ISSUE ]; then 
	if cp $ISSUE $LOG_PATH/ ; then
		echo -e " Get $ISSUE $OK!"
	else
		echo -e " Get $ISSUE $FAILED!"
	fi
else
	echo -e " Not find the $ISSUE!"
fi

if [ -e $SYS_VERSION ]; then
	if cp $SYS_VERSION $LOG_PATH/ ; then
		echo -e " Get $SYS_VERSION $OK!"
	else
		echo -e " Get $SYS_VERSION $FAILED!"
	fi
else
	echo -e " Not find the $SYS_VERSION!"
fi

if [ -e $DNSCONF ]; then
	if cp $DNSCONF $LOG_PATH/resovl.conf.before ; then
		echo -e " Get $DNSCONF $OK!"
	else
		echo -e " Get $DNSCONF $FAILED!"
	fi
else
	echo -e " Not find the $DNSCONF!"
fi

echo -en "Record the route table before VPN connecting ..."
if ($IFCFG & ip r) > $LOG_PATH/ip_route_before_vpn ; then
	echo -e "$TAB $OK!"
else
	echo -e "$TAB $FAILED!"
fi


echo -e "Backup the log message of racoon, and restart the syslog for new log ..."
if [ -e $RACOON_LOG ] && sudo mv $RACOON_LOG $RACOON_LOG.bak 
then
	echo -e " Backup the $RACOON_LOG to $RACOON_LOG.bak $OK!"
else
	echo -e " Backup the $RACOON_LOG $FAILED!"
fi

if [ -e $SYSLOGD ] && sudo $SYSLOGD restart
then
	echo -e " Start the $SYSLOGD $OK!"
else
	echo -e " Restart the $SYSLOGD $FAILED!"
fi

echo -e "Kill the racoon and start it in more debug info ..."
if ps auxw | awk '{print $11}' |  grep -q ra[c]oon ; then
	if sudo pkill `basename $RACOOND`
	then
		echo -e " Kill racoon $OK!"
	else
		echo -e " Kill racoon $FAILED!"
	fi
fi

sleep 1	 # Don't know why, if don't have it, the racoon won't start

if [ -e $SETKEY ]; then
	sudo $SETKEY -D >> $PROCESS_LOG
	sudo $SETKEY -DP >> $PROCESS_LOG
	echo -e "Clear the SAD and SPD befor racoon start"
	sudo $SETKEY -F
	sudo $SETKEY -FP
else
	echo -e "Please install turnpike package!"
fi

if [ -e $RACOOND ]; then
	if sudo $RACOOND -v -d -L -f $RACOON_CONF
	then
		echo -e " Start the $RACOOND $OK!"
	else
		echo -e " Start the $RACOOND $FAILED!"
	fi
else
	echo -e " Can't found you $RACOOND program!"
fi

echo -en "Start the $TCPDUMP at background ..."
#if sudo $TCPDUMP -s 1024 -w $CAPTURE_PKG udp > /dev/null 2>&1 &
if sudo $TCPDUMP -s 1024 -w $CAPTURE_PKG udp &
then
	echo -e "$TAB $OK!"
else
	echo -e "$TAB $FAILED!"
fi

sleep 1

# connect the vpn for test
echo -e "\nThe Profile's list is:"
echo -e "------------------------------------------------"
sele=(`$VPN_CMD -l | sed -n '/File.*profile_/s/File.*profile_\(.*\).prf/\1/p'`)
if [ ${#sele[@]} -eq 0 ]; then
	echo -e "[01;31mPlease use 'vpnlogin' create the profile first![0m"
	sudo pkill `basename $TCPDUMP` # kill the tcpdump also
	exit 0
fi

for ((i=0; i<${#sele[@]}; i++)); do
	echo "[$i] ${sele[i]}" | tee -a $PROCESS_LOG

done

echo -e "------------------------------------------------"
echo -en "Please select the profile's number: "
read num

echo "You select $num!" >> $PROCESS_LOG

if echo $num | egrep -qv '[0-9]+'; then
	echo "Invalid input"
	exit 1
fi
PROFILE=${sele[num]}

echo -e "\nYou select $PROFILE!"

echo -e "Connect the VPN Server now ... (If no response use [01;32mCtrl+C[0m kill it)"

trap "sudo pkill nvpn" INT # capture the Ctrl+C signal, and kill the nvpn, then continue

#($VPN_CMD -v -c $PROFILE ;echo $? >/tmp/ret) | cat # sed -u 's/^/    /'# | tee -a $NVPN_LOG
if $VPN_CMD -v -c $PROFILE ; then
	echo -e "\n\n Test $VPN_CMD $OK!"
else
	echo -e "\n\n Test $VPN_CMD $FAILED!"
fi


echo -en "Record the route table after VPN connecting ..."
if ($IFCFG & ip r) > $LOG_PATH/ip_route_after_vpn ; then
	echo -e "$TAB $OK!"
else
	echo -e "$TAB $FAILED!"
fi

echo -en "Record the ipcfg file..."
if [ -e $IPCFG ]; then
	sudo cp $IPCFG $LOG_PATH
	echo -e "$TAB $OK!"
else
	echo -e "$TAB $FAILED!"
fi

if [ -e $DNSCONF ]; then
	if cp $DNSCONF $LOG_PATH/resolv.conf.after ; then
		echo -e " Get $DNSCONF $OK!"
	else
		echo -e " Get $DNSCONF $FAILED!"
	fi
else
	echo -e " Not find the $DNSCONF!"
fi

if [ -e $SETKEY ]; then
	echo -en "Record the SPD after nvpn conneciton..." >> $PROCESS_LOG
	sudo $SETKEY -D >> $PROCESS_LOG
	sudo $SETKEY -DP >> $PROCESS_LOG
fi

echo -e "Please press any key for VPN Disconnected ..."
read -n 1

echo -e "Disconnect the VPN ..."
if $VPN_CMD -d ; then
	echo -e "$OK!"
else
	echo -e "$FAILED!"
fi

sleep 5 # sleep for wait the shakehand is over

echo -en "Kill the $RACOOND ..."
if sudo pkill `basename $RACOOND` ; then
	echo -e "$TAB $OK!"
else
	echo -e "$TAB $FAILED!"
fi

echo -e "Kill the $TCPDUMP ..."
if sudo pkill `basename $TCPDUMP` ; then
	echo -e "$OK!"
else
	echo -e "$FAILED!"
fi

sleep 1 # wait for the tcpdump's output

if [ -e $SETKEY ]; then
	echo -en "Record the SPD after disconnection..." >> $PROCESS_LOG
	sudo $SETKEY -D >> $PROCESS_LOG
	sudo $SETKEY -DP >> $PROCESS_LOG
fi

# record the turnpike's vendor config file after VPN connected,
# cause racoon will generate some log file.
echo -en "Copy the user's turnpike file ..."
if cp -r $TURNPIKE_PATH $LOG_PATH ; then
	echo -e "$TAB $OK!"
else
	echo -e "$TAB $FAILED!"
fi

echo -en "Copy the racoon's config file ..."
if sudo cp -r $RACOON_PATH $LOG_PATH ; then
	echo -e "$TAB $OK!"
else
	echo -e "$TAB $FAILED!"
fi

echo -en "Copy the racoon's log ..."
if sudo cp $RACOON_LOG $LOG_PATH ; then
	echo -e "$TAB $OK!"
else
	echo -e "$TAB $FAILED!"
fi

echo -en "Tarball the $LOG_PATH ..."
cd $TEMP_PATH
if sudo tar zcf $TAR_FILE $TROUBLESHOOTING ; then
	cd - >/dev/null
	sudo mv $TEMP_PATH/$TAR_FILE .
	echo -e "$TAB $OK! \n\nPlease send the [01;31m$TAR_FILE[0m to maintainer!"
else
       	echo -e "$TAB $FAILED!"
fi
