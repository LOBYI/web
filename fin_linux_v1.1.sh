#!/bin/sh

LANG=C
export LANG

alias ls=ls

CREATE_FILE=`hostname`"_"`date +%Y%m%d`.txt
CHECK_FILE=`ls ./"$CREATE_FILE" 2>/dev/null | wc -l`

# sed -i -e 's/\r$//' fin_linux_ver1.0.sh (윈도우 줄바꿈 에러날 시)
sed -i -e 's/\r$//' aa.sh

echo > $CREATE_FILE 2>&1
clear
echo "******************************** START ********************************" 
echo "********************************************************************" >> $CREATE_FILE 2>&1
echo "*                    CAS(UNIX) 전자금융 Checklist                     *" >> $CREATE_FILE 2>&1
echo "********************************************************************" >> $CREATE_FILE 2>&1
echo "*        Copyright 2018 CAS Co. Ltd. All right Reserved            *" >> $CREATE_FILE 2>&1
echo "********************************************************************" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "########################## Server Release ##########################">> $CREATE_FILE 2>&1
cat /etc/redhat-release >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "############################ Start Time ############################">> $CREATE_FILE 2>&1
date >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "#################### Kernel Information   ##########################" >> $CREATE_FILE 2>&1
uname -a >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "########################## IP Information ###########################" >> $CREATE_FILE 2>&1
ifconfig -a >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "########################### Network Status ###########################" >> $CREATE_FILE 2>&1
netstat -an | egrep -i "LISTEN|ESTABLISHED" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "####################### Routing Information ##########################" >> $CREATE_FILE 2>&1
netstat -rn >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "######################### Process Status #############################" >> $CREATE_FILE 2>&1
ps -ef >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "############################# User Env ###############################" >> $CREATE_FILE 2>&1
env >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "########################## 패스워드 설정 ############################" >> $CREATE_FILE 2>&1
cat /etc/login.defs | grep -v '^#'>> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo >> $CREATE_FILE 2>&1



echo "<##__SRV-001 START__##>"
echo "<##__SRV-001 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-001 SNMP 서비스 community 스트링 설정 오류                               " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - SNMP Community 이름이 public, private 등의 유추하기 쉬운 이름이 아닌 경우" >> $CREATE_FILE 2>&1  
echo "      취약 - SNMP Community 이름이 public, private 등의 유추하기 쉬운 이름인 경우     " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1

echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
snmpcf="/etc/snmp/snmpd.conf /etc/snmp/conf/snmpd.conf"
if [ `ps -ef | egrep -i "snmp|snmpd" | grep -v "grep" | wc -l` -eq 0 ]; then
	echo "SNMP 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
else
	echo "☞ SNMP 실행 여부"  >> $CREATE_FILE 2>&1
	ps -ef | egrep -i "snmp|snmpd" | grep -v "grep"  >> $CREATE_FILE 2>&1
	for line in $snmpcf; do
		echo " " >> $CREATE_FILE 2>&1
		echo "☞ "$line"파일 설정"  >> $CREATE_FILE 2>&1
		if [ -f $line ]; then
			cat $line | grep -A 1 -i 'community'			>> imsi.txt 2>&1
			cat imsi.txt | grep -v "#" | grep -v "-" | grep -v "^$" >> $CREATE_FILE 2>&1
			rm -rf imsi.txt
		else	
			echo $line" 파일이 존재하지 않습니다"  >> $CREATE_FILE 2>&1
		fi
	done
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-001 END__##>"
echo "<##__SRV-001 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "<##__SRV-004 START__##>"
echo "<##__SRV-004 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-004 불필요한 SMTP 서비스 실행 여부                           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 불필요한 SMTP 서비스가 가동되지 않은 경우   " >> $CREATE_FILE 2>&1  
echo "      취약 - 불필요한 SMTP 서비스가 가동되고 있는 경우     " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "sendmail" | grep -v "grep" | wc -l` -eq 0 ]; then
	echo "☞ SMTP 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
 else
	echo "☞ SNMP 실행 여부"  >> $CREATE_FILE 2>&1
	ps -ef | egrep -i "smtp|sendmail" | grep -v "grep" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-004 END__##>"
echo "<##__SRV-004 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "<##__SRV-005 START__##>"
echo "<##__SRV-005 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-005 SMTP 서비스 expn/vrfy 명령어 실행 가능 여부 " 								   >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - noexpn, novrfy 옵션이 설정되어 있는 경우  " 							   >> $CREATE_FILE 2>&1  
echo "      취약 - noexpn, novrfy 옵션이 설정되어 있지 않는 경우 " 						   >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "참고 O PrivacyOptions=authwarnings, goaway로 설정                        "			   >> $CREATE_FILE 2>&1  
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
smtpcf="/etc/mail/sendmail.cf /etc/sendmail.cf"
if [ `ps -ef | egrep -i "smtp|sendmail" | grep -v "grep" | wc -l` -eq 0 ]; then
	echo "Sendmail 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
else
	echo "☞ Sendmail 실행 여부"  >> $CREATE_FILE 2>&1
	ps -ef | egrep -i "smtp|sendmail" | grep -v "grep"  >> $CREATE_FILE 2>&1
	for line in $smtpcf; do
		echo " " >> $CREATE_FILE 2>&1
		echo "☞ "$line"파일 설정"  >> $CREATE_FILE 2>&1
		if [ -f $line ]; then
			cat $line | egrep -i 'O PrivacyOptions|noexpn|novrfy'			>> $CREATE_FILE 2>&1
		else	
			echo $line" 파일이 존재하지 않습니다"  >> $CREATE_FILE 2>&1
		fi
	done
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-005 END__##>"
echo "<##__SRV-005 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-006 START__##>"
echo "<##__SRV-006 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-006 Sendmail Log Level 미설정 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - log level이 적절하게 설정되어 있는 경우   " >> $CREATE_FILE 2>&1  
echo "      취약 - log level이 부적절하게 설정되어 있는 경우     " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
smtpcf="/etc/mail/sendmail.cf /etc/sendmail.cf"
if [ `ps -ef | egrep -i "smtp|sendmail" | grep -v "grep" | wc -l` -eq 0 ]; then
	echo "Sendmail 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
else
	echo "☞ Sendmail 실행 확인"  >> $CREATE_FILE 2>&1
	ps -ef | egrep -i "smtp|sendmail" | grep -v "grep"  >> $CREATE_FILE 2>&1
	for line in $smtpcf; do
		echo " " >> $CREATE_FILE 2>&1
		echo "☞ "$line"파일 설정"  >> $CREATE_FILE 2>&1
		if [ -f $line ]; then
			cat $line | grep -i 'loglevel'			>> $CREATE_FILE 2>&1
		else	
			echo $line" 파일이 존재하지 않습니다"  >> $CREATE_FILE 2>&1
		fi
	done
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-006 END__##>"
echo "<##__SRV-006 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-007 START__##>"
echo "<##__SRV-007 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-007 취약한 버전의 Sendmail 사용 여부 "											   >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - Sendmail 버전 정기적 검토한 경우                            			 " >> $CREATE_FILE 2>&1  
echo "            최신 보안 패치 버전 :  8.15.2(17.07.08 기준) "  						   >> $CREATE_FILE 2>&1  
echo "            send mail관련 취약점 검색 시 *8.14.9 포함 이전버전 취약점 존재 (CVE-2014-3956, 17.07.08 기준) " >> $CREATE_FILE 2>&1
echo "      취약 - Sendmail 버전 정기적으로 검토하지 않은 경우                  "			   >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep -i "smtp|sendmail" | grep -v "grep" | wc -l` -eq 0 ]; then
	echo "Sendmail 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
else
	ps -ef | egrep -i "smtp|sendmail" | grep -v "grep" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
echo "/etc/mail/sendmail.cf 정보" >> $CREATE_FILE 2>&1
echo "----------------------------------------------------" >> $CREATE_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ]; then
	if [ `grep -v '^ *#' /etc/mail/sendmail.cf | grep "DZ" | wc -l` -ge 1 ]; then
		grep -v '^ *#' /etc/mail/sendmail.cf | grep "DZ" >> $CREATE_FILE 2>&1
	else
		echo "sendmail.cf 파일에서 버전 정보를 확인할 수 없습니다." >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/mail/sendmail.cf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-007 END__##>"
echo "<##__SRV-007 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-008 START__##>"
echo "<##__SRV-008 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-008 Sendmail 서비스 거부 방지 기능 미설정 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - MaxDaemonChildren, ConnectionRateThrottle, MinFreeBlocks, MaxHeadersLength, MaxMessageSize" >> $CREATE_FILE 2>&1  
echo "            옵션이 적절하게 설정되어 있는 경우 "  >> $CREATE_FILE 2>&1  
echo "      취약 - 위의 옵션이 설정되어 있지 않은 경우                  " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "[참고] MaxDaemonChildren : 부모 프로세스가 생성 가능한 최대 child 프로세스 수 " >> $CREATE_FILE 2>&1
echo "      ConnectionRateThrottle : 초당 수용 가능한 client 수 " >> $CREATE_FILE 2>&1
echo "      MinFreeBlocks : 메일 수용을 위한 최소 free block " >> $CREATE_FILE 2>&10
echo "      MaxHeadersLength : 수용 가능한 최대 헤더 길이 " >> $CREATE_FILE 2>&1
echo "      MaxMessageSize : 수용 가능한 최대 메시지 길이 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
smtpcf="/etc/mail/sendmail.cf /etc/sendmail.cf"
if [ `ps -ef | egrep -i "smtp|sendmail" | grep -v "grep" | wc -l` -eq 0 ]; then
	echo "Sendmail 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
else
	echo "☞ Sendmail 실행 확인"  >> $CREATE_FILE 2>&1
	ps -ef | egrep -i "smtp|sendmail" | grep -v "grep"  >> $CREATE_FILE 2>&1
	for line in $smtpcf; do
		echo " " >> $CREATE_FILE 2>&1
		echo "☞ "$line"파일 설정"  >> $CREATE_FILE 2>&1
		if [ -f $line ]; then
			cat $line | egrep -i 'MaxDaemonChildren|ConnectionRateThrottle|MinFreeBlocks|MaxHeadersLength|MaxMessageSize'	>> $CREATE_FILE 2>&1
		else	
			echo $line" 파일이 존재하지 않습니다"  >> $CREATE_FILE 2>&1
		fi
	done
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-008 END__##>"
echo "<##__SRV-008 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-009 START__##>"
echo "<##__SRV-009 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-009 스팸 메일 릴레이 제한                                               " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 스팸 메일 릴레이 제한된 경우                                 " >> $CREATE_FILE 2>&1  
echo "            IP <Relay> 설정이 되어있는 경우                              " >> $CREATE_FILE 2>&1
echo "      취약 - 스팸 메일 릴레이 제한이 되지 않은 경우                       " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep 'smtp|sendmail' | grep -v "grep" | wc -l` -eq 0 ]; then
	echo "Sendmail 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
 else
	echo "☞ Sendmail 실행 확인"  >> $CREATE_FILE 2>&1
	ps -ef | egrep 'smtp|sendmail' | grep -v "grep"  >> $CREATE_FILE 2>&1
	echo " "  >> $CREATE_FILE 2>&1
	echo "☞ /etc/mail/sendmail.cf 파일 " >> $CREATE_FILE 2>&1
 	if [ -f /etc/mail/sendmail.cf ]; then
		cat /etc/mail/sendmail.cf | grep -v '^#' | grep -i 'relaying denied' >> $CREATE_FILE 2>&1	
	else 
		echo "/etc/mail/sendmail.cf 파일이 존재하지 않습니다."	 >> $CREATE_FILE 2>&1
	fi
	echo "  " >> $CREATE_FILE 2>&1
		echo "☞ /etc/sendmail.cf 파일 " >> $CREATE_FILE 2>&1
 	if [ -f /etc/sendmail.cf ]; then
		cat /etc/sendmail.cf | grep -v '^#' | grep -i 'relaying denied' >> $CREATE_FILE 2>&1	
	else 
		echo "/etc/mail/sendmail.cf 파일이 존재하지 않습니다."	 >> $CREATE_FILE 2>&1
	fi
	echo "  " >> $CREATE_FILE 2>&1
	echo "☞ /etc/mail/access 파일 " >> $CREATE_FILE 2>&1
	if [ -f /etc/mail/access ]; then
		cat /etc/mail/access | grep -v '^#' | egrep -i 'relay|reject' >> $CREATE_FILE 2>&1	
	else 
		echo "/etc/mail/access 파일이 존재하지 않습니다."	 >> $CREATE_FILE 2>&1
	fi
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-009 END__##>"
echo "<##__SRV-009 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-010 START__##>"
echo "<##__SRV-010 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-010 일반사용자의 Sendmail 실행방지                                      " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 일반 사용자 Sendmail 실행방지 된 경우                        " >> $CREATE_FILE 2>&1  
echo "            [PrivacyOptions 에 restrictqrun 설정이 되어 있는 경우 양호]  " >> $CREATE_FILE 2>&1
echo "      취약 - 일반 사용자 Sendmail 실행방지가 되지 않은 경우               " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
smtpcf="/etc/mail/sendmail.cf /etc/sendmail.cf"
if [ `ps -ef | egrep 'smtp|sendmail' | grep -v "grep" | wc -l` -eq 0 ]; then
	echo "Sendmail 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
else
	echo "☞ Sendmail 실행 확인"  >> $CREATE_FILE 2>&1
	ps -ef | egrep 'smtp|sendmail' | grep -v "grep" >> $CREATE_FILE 2>&1
	for line in $smtpcf; do
		echo " " >> $CREATE_FILE 2>&1
		echo "☞ "$line"파일 설정"  >> $CREATE_FILE 2>&1
		if [ -f $line ]; then
			cat $line | grep -i 'PrivacyOptions'			>> $CREATE_FILE 2>&1
		else	
			echo $line" 파일이 존재하지 않습니다"  >> $CREATE_FILE 2>&1
		fi
	done
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-010 END__##>"
echo "<##__SRV-010 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-011 START__##>"
echo "<##__SRV-011 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-011 ftpusers 파일 내 시스템 계정 존재 여부                 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - ftp 계정을 특정사용자만 접근 가능하도록 설정한 경우           " >> $CREATE_FILE 2>&1  
echo "      취약 - ftp 계정을 특정사용자만 접근 가능하도록 설정하지 않은 경우    " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "ftp" | grep -v grep | wc -l` -eq 0 ]
 then
	echo " FTP가 비실행중입니다."  >> $CREATE_FILE 2>&1
 else
	echo "☞ FTP 실행 확인"  >> $CREATE_FILE 2>&1
	ps -ef | grep "ftp" | grep -v "grep" >> $CREATE_FILE 2>&1
fi
echo "-----------------------------------------"  >> $CREATE_FILE 2>&1
ServiceDIR="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list"
for file in $ServiceDIR
do
	if [ -f $file ]
	then
		echo "☞ "$file"파일 내용"  >> $CREATE_FILE 2>&1
		cat $file | grep -v "#"  >> $CREATE_FILE 2>&1
		echo "-----------------------------------------"  >> $CREATE_FILE 2>&1
	fi
done
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-011 END__##>"
echo "<##__SRV-011 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-012 START__##>"
echo "<##__SRV-012 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-012 .netrc 파일 내 호스트 정보 노출                 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - .netrc 파일의 권한이 적절하게 설정되어 있는 경우           " >> $CREATE_FILE 2>&1  
echo "      취약 - .netrc 파일의 권한이 적절하게 설정되어 않은 경우    " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "ftp" | grep -v grep | wc -l` -eq 0 ]; then
	echo " FTP가 비실행중입니다."													>> $CREATE_FILE 2>&1
else
	echo "☞ FTP 실행 확인"															>> $CREATE_FILE 2>&1
	ps -ef | grep "ftp"	| grep -v grep														>> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "☞ 홈 디렉토리 내 .netrc 파일 확인 "	 >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F: '{print $6}' | sort -u`
for dir in $HOMEDIRS
	do
		if [ -d $dir ] ; then
			ls -alL $dir | awk -F" " '{print $9}' | grep '.netrc' >> ntrcfile.txt
			if [ `cat ntrcfile.txt | wc -l` -eq 0 ] ; then
				echo $dir"디렉토리 내에 .netrc 파일이 없습니다." >> $CREATE_FILE 2>&1
			else
				#echo "☞"$dir" 디렉토리 내 .netrc 파일"  >> $CREATE_FILE 2>&1	
				while read line
				do
					echo "-------------------------------------------------------------------------------------"  >> $CREATE_FILE 2>&1
					echo "[파일 권한]"  >> $CREATE_FILE 2>&1
					ls -aldL $dir/$line >> $CREATE_FILE 2>&1
					echo "[파일 내용]"  >> $CREATE_FILE 2>&1
					cat $dir/$line >> $CREATE_FILE 2>&1
					echo "-------------------------------------------------------------------------------------"  >> $CREATE_FILE 2>&1
				done < ntrcfile.txt
				rm -rf ntrcfile.txt
			fi
		else
			echo $dir"디렉토리가 존재하지 않습니다" >> $CREATE_FILE 2>&1
			
		fi
done
rm -rf ntrcfile.txt
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-012 END__##>"
echo "<##__SRV-012 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-013 START__##>"
echo "<##__SRV-013 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-013 Anonymous FTP 비활성화                                              " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 -  ftp 를 사용하지 않거나, ftp 계정이 존재하지 않을 경우       " >> $CREATE_FILE 2>&1  
echo "             (/etc/services 파일에서 ftp 부분에 주석처리)                " >> $CREATE_FILE 2>&1 
echo "       취약 - ftp 사용시 /etc/passwd 파일에 ftp 계정이 존재할 경우         " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep "ftp" | grep -v grep | wc -l` -ge 1 ]; then
		echo "[1] ftp 서비스 활성화 확인"				>> $CREATE_FILE 2>&1
		ps -ef | grep "ftp" | grep -v grep  >> $CREATE_FILE 2>&1
		echo " "				>> $CREATE_FILE 2>&1
		
		echo "[2] /etc/passwd 파일에서 FTP 계정 확인"				>> $CREATE_FILE 2>&1
		if [ `cat /etc/passwd | egrep 'ftp|anonymous' | wc -l` -eq 0 ]; then
			echo "ftp 관련 계정이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		else
			cat /etc/passwd | egrep 'ftp|anonymous' >> $CREATE_FILE 2>&1
		fi
		echo " "				>> $CREATE_FILE 2>&1
		
		echo "[3] Anonymouse 설정 확인"				>> $CREATE_FILE 2>&1
		#전자금융기반시설에 나온 conf파일 
		vsDIR="/etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/vsftpd/conf/vsftpd.conf"
		for file in $vsDIR
		do
			if [ -f $file ]
			then
				echo "------------------------------------"				>> $CREATE_FILE 2>&1
				echo "☞ "$file" 파일 내용"  >> $CREATE_FILE 2>&1
				cat $file | grep 'anonymous' | grep -v '^#' >> $CREATE_FILE 2>&1
				echo "------------------------------------"				>> $CREATE_FILE 2>&1
			else	
				echo $file"파일이 존재하지 않습니다" >> $CREATE_FILE 2>&1
			fi
		done
		proDIR="/etc/proftpd.conf /etc/proftpd/proftpd.conf /etc/proftpd/conf/proftpd.conf /usr/local/etc/proftpd.conf /usr/local/proftpd/etc/proftpd.conf"
		for file in $proDIR
		do
			if [ -f $file ]
			then
				echo "------------------------------------"				>> $CREATE_FILE 2>&1
				echo "☞ "$file" 파일 내용"  >> $CREATE_FILE 2>&1
				cat $file | grep -v '^#' >> $CREATE_FILE 2>&1
				echo "------------------------------------"				>> $CREATE_FILE 2>&1
			else	
				echo $file"파일이 존재하지 않습니다" >> $CREATE_FILE 2>&1
			fi
		done
		ftpadir="/etc/ftpaccess /etc/ftpd/ftpaccess"
		for file in $ftpadir
		do
			if [ -f $file ]; then
				echo "------------------------------------"				>> $CREATE_FILE 2>&1
				echo $file" 파일 내용" >> $CREATE_FILE 2>&1
				cat $file | grep -v '^#' >> $CREATE_FILE 2>&1
				echo "------------------------------------"				>> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
			else
				echo $file"파일이 존재하지 않습니다" >> $CREATE_FILE 2>&1
			fi	
		done
	else
echo "FTP 서비스가 비활성화 되어 있습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-013 END__##>"
echo "<##__SRV-013 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-014 START__##>"
echo "<##__SRV-014 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-014  NFS 접근통제                                                        " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - NFS 서비스를 사용하지 않거나, 사용 시 everyone 공유를 제한한 경우 " >> $CREATE_FILE 2>&1  
echo "      취약 - NFS 서비스를 사용하고 있고, everyone 공류를 제한하지 않은 경우    " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
nfscf="/etc/dfs/dfstab /etc/dfs/sharetab /etc/exports /etc/netroup"
echo "[1] NFS 설정 파일의 권한 확인(권한 644, 소유자 root)"				>> $CREATE_FILE 2>&1
for lines in $nfscf; do
	if [ -f $lines ]; then
		ls -al $lines 							>> $CREATE_FILE 2>&1
	else
		echo $lines" 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
	fi
done
echo " "				                                            >> $CREATE_FILE 2>&1
echo "[2] 설정파일 내용 확인"											>> $CREATE_FILE 2>&1
for lines in $nfscf; do
	if [ -f $lines ]; then
		echo "--------------------------------------"				>> $CREATE_FILE 2>&1
		echo "☞ "$lines" 파일 내용"									>> $CREATE_FILE 2>&1
		cat $lines 													>> $CREATE_FILE 2>&1
		echo "--------------------------------------"				>> $CREATE_FILE 2>&1
	else
		echo $lines" 파일이 존재하지 않습니다."  							>> $CREATE_FILE 2>&1
	fi
done
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-014 END__##>"
echo "<##__SRV-014 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-015 START__##>"
echo "<##__SRV-015 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-015   NFS 서비스 비활성화                                                 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 불필요한 NFS 서비스 비활성화 된 경우                         " >> $CREATE_FILE 2>&1  
echo "      취약 - 불필요한 NFS 서비스 활성화 된 경우                           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ ps -ef 명령어 확인" >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep 'nfs|statd|lockd' |wc -l` -ge 1 ]; then
	ps -ef | egrep 'nfs|statd|lockd' | grep -v grep >> $CREATE_FILE 2>&1 >> $CREATE_FILE 2>&1
else
	echo "nfs 관련 프로세스가 검색되지 않았습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-015 END__##>"
echo "<##__SRV-015 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-016 START__##>"
echo "<##__SRV-016 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-016  불필요한 RPC 서비스 확인                                                     " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 불필요한 RPC 서비스가 비활성화 되어 있는 경우              " >> $CREATE_FILE 2>&1  
echo "      취약 - 불필요한 RPC 서비스가 활성화 되어 있는 경우                           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
#전자금융 기준에서 점검하는 리스트 
SERVICE_INETD="cms ttdbserver sadmin rusers wall spray rstat stat nis rex pcnfs ypserv ypbind ypxfrd yppasswdd ypupdated rquota kcms_server cachefs rpc"
echo "------------------------------------------------" >> $CREATE_FILE 2>&1
echo "서비스 포트 활성화 여부 확인" >> $CREATE_FILE 2>&1
echo "------------------------------------------------" >> $CREATE_FILE 2>&1
echo "☞ 커널 2.X 이하(inetd 사용 시)" >> $CREATE_FILE 2>&1
for lists in SERVICE_INETD; do
	if [ -f /etc/inetd.conf ]; then
		if [ `cat /etc/inetd.conf | grep -i $lists | wc -l` -ge 1 ]; then
			cat /etc/inetd.conf | grep -i $lists >> $CREATE_FILE 2>&1
		else
			echo "rpc 프로세스가 검색되지 않았습니다." >> $CREATE_FILE 2>&1
		fi
	else
		echo "/etc/inetd.conf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi
done
echo " " >> $CREATE_FILE 2>&1
echo "☞ 커널 2.X 이상(xinetd 사용 시)" >> $CREATE_FILE 2>&1
if [ -d /etc/xinetd.d ]; then
	for list in $SERVICE_INETD; do
		if [ -f /etc/xinetd.d/$list ]; then
			echo "▷ "$list" 서비스 "  >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/$list | grep -i disable  >> $CREATE_FILE 2>&1
		else
			echo $list" 프로세스가 검색되지 않았습니다." >> $CREATE_FILE 2>&1
		fi
	done
else
	echo "/etc/xinetd.d 디렉토리가 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "------------------------------------------------" >> $CREATE_FILE 2>&1
echo "프로세스 활성화 확인" >> $CREATE_FILE 2>&1
echo "------------------------------------------------" >> $CREATE_FILE 2>&1
for lists in SERVICE_INETD; do
if [ `ps -ef  | grep $lists |grep -v "grep" |wc -l` -ge 1 ]; then
		ps -ef  | grep $lists |grep -v "grep" >> $CREATE_FILE 2>&1
	else
		echo "rpc 프로세스가 검색되지 않았습니다." >> $CREATE_FILE 2>&1
fi
done
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-016 END__##>"
echo "<##__SRV-016 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-017 START__##>"
echo "<##__SRV-017 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-017  automountd 제거                                                     " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - automountd를 제거 했을 경우                                  " >> $CREATE_FILE 2>&1  
echo "      취약 - automountd를 제거 하지 않았을 경우                           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep "automountd|autofs" | grep -v "grep" |wc -l` -ge 1 ]; then
	ps -ef | egrep "automount|automountd|autofs" | grep -v "grep" >> $CREATE_FILE 2>&1
else
	echo "automountd, autofs 서비스가 구동중이지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-017 END__##>"
echo "<##__SRV-017 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-019 START__##>"
echo "<##__SRV-019 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-019 tftp, talk 서비스 비활성화                                          " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - tftp, talk 서비스를 비활성화 한 경우                         " >> $CREATE_FILE 2>&1  
echo "      취약 - tftp, talk 서비스를 활성화 한 경우                           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
echo "inetd 사용 시" >> $CREATE_FILE 2>&1
echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]; then
	if [ `cat /etc/inetd.conf | egrep -i "tftp|talk|ntalk" | wc -l` -ge 1 ]; then
		cat /etc/inetd.conf | egrep -i "tftp|talk|ntalk" >> $CREATE_FILE 2>&1
	else
		echo "tftp, talk, ntalk 서비스가 검색되지 않습니다." >> $CREATE_FILE 2>&1
	fi
else
	echo "inetd.conf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
echo "xinetd 사용 시" >> $CREATE_FILE 2>&1
echo "-----------------------------------------------" >> $CREATE_FILE 2>&1
tftpsv='tftp talk ntalk'
for list in $tftpsv; do
if [ -d /etc/xinetd.d ]; then
	if [ -f  /etc/xinetd.d/$list ]; then
		ls -al /etc/xinetd.d/$list >> $CREATE_FILE 2>&1
		cat /etc/xinetd.d/$list | grep -i disable >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo $list" 서비스가 검색되지 않습니다." >> $CREATE_FILE 2>&1
	fi
else
	echo "xinetd.d 디렉토리가 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
done
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-019 END__##>"
echo "<##__SRV-019 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-022 START__##>"
echo "<##__SRV-022 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-022 계정의 비밀번호 미 설정 점검                                      " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 계정에 비밀번호가 설정되어 있는 경우                         " >> $CREATE_FILE 2>&1  
echo "      취약 - 계정에 비밀번호가 설정되어 있지 않거나 빈 비밀번호를 설정하지 않은 경우    " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "[참고] PS : 정상적인 패스워드 존재" >> $CREATE_FILE 2>&1
echo "       LK : 계정이 잠겨있거나 패스워드가 NP인 경우" >> $CREATE_FILE 2>&1
echo "       NP : 패스워드가 없는 경우" >> $CREATE_FILE 2>&1
echo "       NL : 로그인 한 적이 없는 계정" >> $CREATE_FILE 2>&1
echo "       UN : 암호 필드의 데이터를 알 수 없는 계정" >> $CREATE_FILE 2>&1
echo "       UP : 아직 관리자가 활성화하지 않아 사용할 수 없는 계정" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
cat /etc/passwd | awk -F":" {'print $1'} >> userid.txt
while read line 
do
	passwd -S $line | grep --regex=.*	>> $CREATE_FILE 2>&1
done < userid.txt
rm -rf userid.txt
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-022 END__##>"
echo "<##__SRV-022 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-025 START__##>"
echo "<##__SRV-025 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-025 \$HOME/.rhosts, hosts.equiv 사용 금지                               " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - $HOME /.rhosts, hosts.equiv 활성화를 시키지 않았을 경우      " >> $CREATE_FILE 2>&1  
echo "            [파일권한 600이하, 소유자 root, + + 설정이 없는 경우]        " >> $CREATE_FILE 2>&1
echo "      취약 - $HOME /.rhosts, hosts.equiv 활성화된 경우                    " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
equivfiles="/etc/hosts /etc/hosts.equiv"
rservice='rlogin rcp rcmd rexec rshell'
echo "------------------------------------" >> $CREATE_FILE 2>&1
echo "서비스 구동 확인" >> $CREATE_FILE 2>&1
echo "------------------------------------" >> $CREATE_FILE 2>&1
echo "☞ ps -ef 확인" >> $CREATE_FILE 2>&1
for list in $rservice; do
if [ `ps -ef | grep $list | grep -v grep | wc -l` -eq 0 ]; then
	echo $list" 서비스가 구동 중이지 않음" >> $CREATE_FILE 2>&1
else
	ps -ef | grep $list | grep -v grep  >> $CREATE_FILE 2>&1
fi
done
echo " " >> $CREATE_FILE 2>&1
echo "☞ inetd.conf 확인" >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]; then
	for list in $rservice; do
		cat /etc/inetd.conf | grep $list >> $CREATE_FILE 2>&1
	done
else
	echo "inetd.conf 파일이 존재하지 않습니다.">> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "☞ xinetd.d 확인" >> $CREATE_FILE 2>&1
if [ -d /etc/xinetd.d ]; then
	for list in $rservice; do
		if [ -f /etc/xinetd.d/$list ]; then
			cat /etc/xinetd.d/$list | grep -i disable >> $CREATE_FILE 2>&1
		else 
			echo $list" 서비스가 검색되지 않습니다." >> $CREATE_FILE 2>&1
		fi
	done
else
	echo "xinetd.conf 디렉토리가 존재하지 않습니다.">> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
for file in $equivfiles; do
	if [ -f $file ]; then
		echo "------------------------------------" >> $CREATE_FILE 2>&1
		echo "☞ "$file"내용" >> $CREATE_FILE 2>&1
		echo "------------------------------------" >> $CREATE_FILE 2>&1
		ls -al $file >> $CREATE_FILE 2>&1
		cat $file >> $CREATE_FILE 2>&1
		echo " "				>> $CREATE_FILE 2>&1
	else
		echo $file"파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi
done
echo " " >> $CREATE_FILE 2>&1
echo "------------------------------------" >> $CREATE_FILE 2>&1
echo "/.rhosts 파일 내용"				>> $CREATE_FILE 2>&1
echo "------------------------------------" >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
	for dir in $HOMEDIRS
	do
		if [ ! -f $dir/.rhosts ] ; 				then
			echo $dir"/.rhosts 파일이 존재하지 않습니다" >> $CREATE_FILE 2>&1
		else
			echo "------------------------------------" >> $CREATE_FILE 2>&1
			echo "☞"$dir"/.rhosts 파일내용"  >> $CREATE_FILE 2>&1
			echo "------------------------------------" >> $CREATE_FILE 2>&1
			cat $dir/.rhosts >> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
		fi
	done		
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-025 END__##>"
echo "<##__SRV-025 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "<##__SRV-026 START__##>"
echo "<##__SRV-026 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-026  root 계정 원격 접속 제한                                            " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 원격 접속 시 root 로 바로 접속 가능 하지 않도록 설정되어 있는 경우 " >> $CREATE_FILE 2>&1  
echo "      취약 - 원격 접속 시 root 로 바로 접속 가능 하도록 설정되어 있을 경우 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ /etc/securetty 파일 설정(telnet 사용 시 root 접근 제한 설정)" >> $CREATE_FILE 2>&1
echo "  파일 내에 pts 설정이 존재하는 경우 PAM 모듈 설정과 관계없이 root 계정 접속을 허용하므로" >> $CREATE_FILE 2>&1
echo "  반드시 securetty 파일에서 pts/x 관련 설정 제거 필요" >> $CREATE_FILE 2>&1
if [ -f /etc/securetty ]; then
	cat /etc/securetty | egrep -i "(ptyp1|^pts)"             >> $CREATE_FILE 2>&1
else
	echo "/etc/securetty 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >>$CREATE_FILE 2>&1
echo "☞ /etc/pam.d/remote 파일 설정" >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/remote ]; then
	cat /etc/pam.d/remote | grep -i "pam_securetty.so"             >> $CREATE_FILE 2>&1
else
	echo "/etc/pam.d/remote 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >>$CREATE_FILE 2>&1
echo "☞ /etc/pam.d/login 파일 설정" >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/login ]; then
	cat /etc/pam.d/login | grep -i "pam_securetty.so"             >> $CREATE_FILE 2>&1
else
	echo "/etc/pam.d/login 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >>$CREATE_FILE 2>&1
#전자금융 sshd 설정파일 확인 추가
echo "☞ ssh 설정 파일"				                                      >> $CREATE_FILE 2>&1
FILE_SSHD_CONF="/etc/ssh/sshd_config /opt/ssh/etc/sshd_config /etc/sshd_config /usr/local/etc/sshd_config /usr/local/sshd/etc/sshd_config /usr/local/ssh/etc/sshd_config /etc/ssh/ssh_config"
for SSHD_CONF in $FILE_SSHD_CONF; do
	if [ -f $SSHD_CONF ]; then
		cat $SSHD_CONF | egrep -i "(PermitRootLogin|denyuser)"                           >> $CREATE_FILE 2>&1
	fi
done
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-026 END__##>"
echo "<##__SRV-026 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-027 START__##>"
echo "<##__SRV-027 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-027  접속 IP 및 포트 제한                                                " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 방화벽 설정이 되어 있거나 시스템에서 접근제어 설정이 된 경우 " >> $CREATE_FILE 2>&1  
echo "            [IP 주소로 지정된 경우]                                      " >> $CREATE_FILE 2>&1
echo "      취약 - 방화벽 설정이 없거나, 접근제어 설정이 없는 경우              " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "---------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "▶ TCP Warraper 사용 시" >> $CREATE_FILE 2>&1
echo "---------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "☞ hosts.allow 파일 내용" >> $CREATE_FILE 2>&1
if [ -f /etc/hosts.allow ]; then
	cat /etc/hosts.allow  | grep -v '^#' >> $CREATE_FILE 2>&1
else
	echo "/etc/hosts.allow 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "☞ hosts.deny 파일 내용" >> $CREATE_FILE 2>&1
if [ -f /etc/hosts.deny ]; then
	cat /etc/hosts.deny | grep -v '^#'>> $CREATE_FILE 2>&1
else
	echo "/etc/hosts.deny 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "---------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "▶ IP tables 사용 시" >> $CREATE_FILE 2>&1
echo "---------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "☞ 구동 확인" >> $CREATE_FILE 2>&1
#service iptables status >> $CREATE_FILE 2>&1
systemctl status iptables >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ 설정 확인" >> $CREATE_FILE 2>&1
iptables -L >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "---------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "▶ Firewall 사용 시" >> $CREATE_FILE 2>&1
echo "---------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "☞ 구동확인" >> $CREATE_FILE 2>&1
firewall-cmd --state >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ 설정 확인" >> $CREATE_FILE 2>&1
z1=`firewall-cmd --get-default-zone`
echo "[알려진 서비스명]" >> $CREATE_FILE 2>&1
firewall-cmd --zone=$z1 --list-services >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "[포트]" >> $CREATE_FILE 2>&1
firewall-cmd --zone=$z1 --list-ports >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
#echo "---------------------------------------------------------------" >> $CREATE_FILE 2>&1
#echo "▶ ufw 사용 시 (Ubuntu에서만 해당)" >> $CREATE_FILE 2>&1
#echo "---------------------------------------------------------------" >> $CREATE_FILE 2>&1
#ufw status >> $CREATE_FILE 2>&1
#echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-027 END__##>"
echo "<##__SRV-027 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "<##__SRV-030 START__##>"
echo "<##__SRV-030 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-030  Finger 서비스 비활성화                                              " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 불필요한 Finger 서비스가 비활성화 된 경우                    " >> $CREATE_FILE 2>&1  
echo "      취약 - 불필요한 Finger 서비스가 활성화 된 경우                      " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
	if [ `ps -ef | grep 'finger' | grep -v grep | wc -l` -ge 1 ]; then
		ps -ef | grep 'finger' | grep -v grep  >> $CREATE_FILE 2>&1
	elif [ `cat /etc/services | grep "finger" | wc -l` -ge 1 ]; then
		cat /etc/services | grep "finger" >> $CREATE_FILE 2>&1
		else
			echo "Finger 서비스 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
	fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-030 END__##>"
echo "<##__SRV-030 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-035 START__##>"
echo "<##__SRV-035 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-035  r 계열 서비스 비활성화                                              " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - rlogin, rshell, rexec 서비스가 구동중이 않을 경우            " >> $CREATE_FILE 2>&1  
echo "      취약 - rlogin, rshell, rexec 서비스가 구동중일 경우                 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "------------------------------------------------" >> $CREATE_FILE 2>&1
echo "☞ 커널 2.X 이하(inetd 사용 시)" >> $CREATE_FILE 2>&1
echo "------------------------------------------------" >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]
        then
           cat /etc/inetd.conf | grep –i 'rshell|rsh|rlogin|rexec|rcp' >> $CREATE_FILE 2>&1
        else
          echo "/etc/inetd.conf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "------------------------------------------------" >> $CREATE_FILE 2>&1
echo "커널 2.X 이상(xinetd 사용 시)" >> $CREATE_FILE 2>&1
echo "------------------------------------------------" >> $CREATE_FILE 2>&1
if [ -d /etc/xinetd.d ]
        then
           systemctl list-unit-files | egrep -i "rshell|rsh|rlogin|rexec|rcp" >> $CREATE_FILE 2>&1
			xinet=`ls -p /etc/xinetd.d/ | grep -v '/$'`

		   for x_set in $xinet; do
				echo $x_set >> $CREATE_FILE 2>&1
				echo `cat /etc/xinetd.d/$x_set | grep disable` >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
		   done
		else
          echo "/etc/xinetd.d 디렉토리가 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-035 END__##>"
echo "<##__SRV-035 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-036 START__##>"
echo "<##__SRV-036 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-036  DoS 공격에 취약한 서비스 비활성화                                   " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - DoS 공격에 취약한 서비스를 사용하지 않을 경우                " >> $CREATE_FILE 2>&1  
echo "      취약 - DoS 공격에 취약한 서비스를 사용하는 경우                     " >> $CREATE_FILE 2>&1
echo "            [취약한 서비스 : echo, discard, daytime, chargen]            " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "------------------------------------------------" >> $CREATE_FILE 2>&1
echo "inetd 사용 시 (커널 2.x 이하)" >> $CREATE_FILE 2>&1
echo "------------------------------------------------" >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]
        then
           cat /etc/inetd.conf | egrep –i 'echo|discard|daytime|chargen' >> $CREATE_FILE 2>&1
        else
          echo "/etc/inetd.conf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "------------------------------------------------" >> $CREATE_FILE 2>&1
echo "Xinetd 사용 시 (커널 2.x 이상)" >> $CREATE_FILE 2>&1
echo "------------------------------------------------" >> $CREATE_FILE 2>&1
doslist='echo discard daytime chargen'
for list in $doslist; do
	if [ -d /etc/xinetd.d ]; then
		if [ -f /etc/xinetd.d/$list ]; then
			echo "☞ "$list" 서비스"
				cat /etc/xinetd.d/$list | grep -i disable >> $CREATE_FILE 2>&1
			else
				echo $list" 서비스가 검색되지 않습니다" >> $CREATE_FILE 2>&1
			fi
	else
		echo "/etc/xinetd.d 디렉토리가 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi
done
echo " " >> $CREATE_FILE 2>&1	
echo "<##__SRV-036 END__##>"
echo "<##__SRV-036 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-037 START__##>"
echo "<##__SRV-037 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-037 FTP 서비스 구동 점검                                                     " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - ftp 서비스를 비활성화 한 경우                                " >> $CREATE_FILE 2>&1  
echo "      취약 - ftp 서비스를 활성화 한 경우                                  " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "ftp" | grep -v grep | wc -l` -eq 0 ]
 then
   echo " FTP가 비실행중입니다."  >> $CREATE_FILE 2>&1
 else
   ps -ef | grep "ftp" | grep -v grep >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-037 END__##>"
echo "<##__SRV-037 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-039 START__##>"
echo "<##__SRV-039 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-039 불필요한 Tmax WebtoB 서비스 구동 여부                                            " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 불필요한 Tmax WebtoB 서비스가 구동되지 않은 경우                         " >> $CREATE_FILE 2>&1  
echo "      취약 - 불필요한 Tmax WebtoB 서비스가 구동되고 있는 경우                           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep -i 'wsm|webtob' | grep -v grep | wc -l` -eq 0 ]
 then
   echo "webtob가 비실행중입니다."  >> $CREATE_FILE 2>&1
 else
   ps -ef | egrep -i 'wsm|webtob'| grep -v grep  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-039 END__##>"
echo "<##__SRV-039 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "================================= httpd.conf 파일 경로 =================================" >> $CREATE_FILE 2>&1

# 존재하는 모든 httpd.conf 파일
#find / -name 'httpd.conf' >> conffilelist.txt
#cat conffilelist.txt  >> $CREATE_FILE 2>&1
apacheD=`ps -ef | egrep 'apache|httpd' | grep -v grep | awk '{for (i=1;i<=NF;i++) {if ($i ~/(bin)/) {print $i}}}' | egrep 'httpd$|httpd2$|apache$|apache2$' | grep -v "grep" | sort -u`
if [ $apacheD ]; then
	# httpd -V 옵션으로 webroot 디렉토리와 conf 파일의 위치 파악가능
	webroot=`$apacheD -V | grep ROOT | awk -F= '{print $2}' | sed s/\"//g`
	webconf_file=`$apacheD -V | grep SERVER | awk -F= '{print $2}' | sed s/\"//g`
	if [ $webconf_file ]; then
		# httpd -V 결과 중 conf 설정 값이 상대경로 혹은 절대경로로 나올 수 있으므로, 모두 절대경로로 나오도록 설정
		#if [ ${webconf_file:0:1} != "/" ]; then
		#	webconf_file="${webroot}/${webconf_file}"
		#fi
		webconf_temp=`echo "$webconf_file" | egrep "^[^\/]"`
		if [ "$webconf_temp" ]; then
			webconf_file="${webroot}/${webconf_file}"
		fi
	else
		if [ -f /etc/httpd/conf/httpd.conf ]; then
			webconf_file="/etc/httpd/conf/httpd.conf"
		elif [ -f /web/httpd/conf/httpd.conf ]; then
			webconf_file="/web/httpd/conf/httpd.conf"
		fi
	fi
	if [ -f "$webconf_file" ]; then
		# document root 경로도 변수로 저장하여 활용
		web_docuroot=`cat $webconf_file | grep "DocumentRoot" | sed "s/&/\&amp;/g" | sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"`
	fi
fi
if [ -f "$webconf_file" ]; then
	ls -al $webconf_file >> $CREATE_FILE 2>&1
else
	echo "httpd 설정 파일이 존재하지 않습니다.">> $CREATE_FILE 2>&1
fi
echo "======================================================================================" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-040 START__##>"
echo "<##__SRV-040 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################"	>> $CREATE_FILE 2>&1
echo "SRV-040 Apache 디렉터리 리스팅 제거                                         " 			>> $CREATE_FILE 2>&1
echo "#######################################################################################"	>> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 디렉터리 리스팅을 제거하거나 방지했을 경우                   " 				>> $CREATE_FILE 2>&1  
echo "            Indexes 삭제되어 있거나 IncludesNoExec 또는 -Indexes 된 경우 " 		>> $CREATE_FILE 2>&1  
echo "      취약 - 디렉터리 리스팅을 제거하거나 방지하지 않았을 경우            " 			>> $CREATE_FILE 2>&1
echo "#######################################################################################" 		>> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "grep" | wc -l` -ge 1 ] ; then
	if [ -f "$webconf_file" ]; then
		cat "$webconf_file" | egrep -i '<directory|Indexes|IncludesNoExec|</directory' | grep -v '#'>> $CREATE_FILE 2>&1
	else
		echo $webconf_file"이 존재하지 않습니다">> $CREATE_FILE 2>&1
	fi
else
	echo "Apache Disable"									>> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-040 END__##>"
echo "<##__SRV-040 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-042 START__##>"
echo "<##__SRV-042 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-042 Apache 상위 디렉토리 접근 금지                                      " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 상위 디렉토리에 접근을 제한한 경우                           " >> $CREATE_FILE 2>&1  
echo "            [Directory 부분의 AllowOverride AuthConfig 설정]              " >> $CREATE_FILE 2>&1  
echo "      취약 - 상위 디렉토리에 접근이 가능한 경우                           " >> $CREATE_FILE 2>&1
echo "            [Directory부분의 AllowOverride None 설정]         		     " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "grep" | wc -l` -ge 1 ] ; then
	if [ -f "$webconf_file" ]; then
		cat "$webconf_file" | egrep -i '<directory|AllowOverride|</directory' | grep -v '#'			>> $CREATE_FILE 2>&1
	else
		echo $webconf_file"이 존재하지 않습니다">> $CREATE_FILE 2>&1
	fi
else
	echo "Apache Disable"									>> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-042 END__##>"
echo "<##__SRV-042 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-043 START__##>"
echo "<##__SRV-043 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-043 Apache 불필요한 파일 제거                                           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 불필요한 파일이 없을 경우                                    " >> $CREATE_FILE 2>&1  
echo "            [/htdocs/manual, /cgi-bin/test-cgi , printenv 없을 경우 ]     " >> $CREATE_FILE 2>&1 
echo "			  [불필요한 파일] 샘플 파일, 매뉴얼 파일, 임시 파일, 테스트 파일, 백업 파일 등 "  >> $CREATE_FILE 2>&1 
echo "      취약 - 불필요한 파일이 존재할 경우                                  " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
#금보원 스크립트에서는 cgi-bin 파일만 확인함
if [ `ps -ef | grep "httpd" | grep -v "grep" | wc -l` -ge 1 ] ; then
if [ -d "$webroot" ]; then
	if [ `find $webroot -name '*cgi-bin*' -exec ls -al {} \; | wc -l` -ge 1 ]; then
		find $webroot -name '*cgi-bin*' -exec ls -al {} \; >> $CREATE_FILE 2>&1
	else
		echo "cgi-bin 관련 파일이 발견되지 않습니다." >> $CREATE_FILE 2>&1
	fi
	#find $webroot -name '*manual*' -exec ls -al {} \; >> $CREATE_FILE 2>&1
	#find $webroot -name '*printenv*' -exec ls -al {} \; >> $CREATE_FILE 2>&1
else
	echo "디렉토리가 가 존재하지 않습니다."  >> $CREATE_FILE 2>&1
fi
else
	echo "Apache Disable"									>> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-043 END__##>"
echo "<##__SRV-043 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-044 START__##>"
echo "<##__SRV-044 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-044 Apache 파일 업로드 및 다운로드 제한                                 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 파일 업로드, 다운로드 용량제한 설정이 된 경우                " >> $CREATE_FILE 2>&1  
echo "            [Directory 경로의 LimitRequestBody 용량 제한 설정이된 경우]   " >> $CREATE_FILE 2>&1  
echo "      취약 - 파일 업로드, 다운로드 용량제한 설정되지 않은 경우            " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "grep" | wc -l` -ge 1 ] ; then
	if [ -f "$webconf_file" ]; then
		cat "$webconf_file" | egrep -i '<directory|LimitRequestBody|</directory' | grep -v '#'			>> $CREATE_FILE 2>&1
	else
		echo $webconf_file"이 존재하지 않습니다">> $CREATE_FILE 2>&1
	fi
else
	echo "Apache Disable"									>> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-044 END__##>"
echo "<##__SRV-044 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-045 START__##>"
echo "<##__SRV-045 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-045 Apache 웹 프로세스 권한 제한                                        " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 웹 프로세스 권한을 제한 했을 경우                            " >> $CREATE_FILE 2>&1  
echo "            [root이외의 오직 apache구동 계정일 경우]                     " >> $CREATE_FILE 2>&1  
echo "      취약 - 웹 프로세스 권한을 제한 하지 않았을 경우                     " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "grep" | wc -l` -ge 1 ] ; then
	if [ -f "$webconf_file" ]; then
		cat "$webconf_file" | egrep -i '^user|^group' | grep -v '#'			>> $CREATE_FILE 2>&1
	else
		echo $webconf_file"이 존재하지 않습니다">> $CREATE_FILE 2>&1
	fi
else
	echo "Apache Disable"									>> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1		
echo "<##__SRV-045 END__##>"
echo "<##__SRV-045 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-046 START__##>"
echo "<##__SRV-046 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-046 Apache 웹 서비스 영역의 분리                                        " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - DocumentRoot를 별도의 디렉터리로 지정한 경우                 " >> $CREATE_FILE 2>&1  
echo "            [홈디렉터리가 /apache/htdocs등 default경로가 아닌 경우]       " >> $CREATE_FILE 2>&1  
echo "      취약 - DocumentRoot를 별도의 디렉터리로 지정하지 않은 경우          " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "grep" | wc -l` -ge 1 ] ; then
	if [ -f "$webconf_file" ]; then
		cat "$webconf_file" | egrep -i '<directory|DocumentRoot|</directory' | grep -v '#'			>> $CREATE_FILE 2>&1
	else
		echo $webconf_file"이 존재하지 않습니다">> $CREATE_FILE 2>&1
	fi
else
	echo "Apache Disable"									>> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-046 END__##>"
echo "<##__SRV-046 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-047 START__##>"
echo "<##__SRV-047 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-047 Apache 링크 사용 금지                                               " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 심볼릭 링크, aliases을 사용하지 않을 경우                    " >> $CREATE_FILE 2>&1  
echo "            [Options에 FollowSymLinks 가 제거된 경우 ]                     " >> $CREATE_FILE 2>&1  
echo "      취약 - 심볼릭 링크, aliases을 사용할 경우                           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "grep" | wc -l` -ge 1 ] ; then
	if [ -f "$webconf_file" ]; then
		cat "$webconf_file" | egrep -i '<directory|FollowSymLinks|</directory' | grep -v '#'			>> $CREATE_FILE 2>&1
	else
		echo $webconf_file"이 존재하지 않습니다">> $CREATE_FILE 2>&1
	fi
else
	echo "Apache Disable"									>> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-047 END__##>"
echo "<##__SRV-047 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-060 START__##>"
echo "<##__SRV-060 START__##>"		>> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-060 미흡한 Apache Tomcat 기본 계정 사용 여부                                      " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 기본적으로 설정되는 tomcat 계정/패스워드를 사용하지 않는 경우                " >> $CREATE_FILE 2>&1  
echo "       취약 - 기본적으로 설정되는 tomcat 계정/패스워드를 사용하는 경우         " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
CATALINA_HOME=`ps auxwww | egrep 'catalina\.startup\.Bootstrap' | egrep -v "grep|java -server" | awk '{for (i=1;i<=NF;i++) {if ($i ~/(Dcatalina\.home)/) {print $i}}}' | awk -F"=" '{ print $2 }' | grep '^/' | sort -u |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"`
echo $CATALINA_HOME >> catalinahome.txt
if [ `ps auxwww | egrep 'catalina\.startup\.Bootstrap' | egrep -v "grep|java -server" | awk '{for (i=1;i<=NF;i++) {if ($i ~/(Dcatalina\.home)/) {print $i}}}' | awk -F"=" '{ print $2 }' | grep '^/' | sort -u | wc -l` -ge 1 ] ; then
	if [ `cat catalinahome.txt | wc -l` -eq 0 ]; then
	echo "tomcat Disable"
	echo "tomcat Disable"																				>> $CREATE_FILE 2>&1
else
	echo "tomcat Enable"
	echo "tomcat Enable / 스크립트 결과 맨 아랫부분 참조"														>> $CREATE_FILE 2>&1
	fi
else
	echo "Tomcat Disable"
	echo "tomcat Disable"																				>> $CREATE_FILE 2>&1
fi
rm -rf catalinahome.txt
echo "<##__SRV-060 END__##>"
echo "<##__SRV-060 END__##>"		>> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-061 START__##>"
echo "<##__SRV-061 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-061  DNS Inverse Query 설정 오류                                             " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - DNS Inverse Query 설정 오류에 대해 적절한 보안 설정을 한 경우                  " >> $CREATE_FILE 2>&1  
echo "      취약 - DNS Inverse Query 설정 오류에 대해 보안 설정이 되어 있지 않은 경우       " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "[참 고] BIND 4 시리즈 중 4.9.7 이전버전과 BIND 8 시리즈 중 8.1.2 이전 버전은			" >> $CREATE_FILE 2>&1
echo "		 외부에서 inverse query 요청에 대하여 응답을 수행할 때 메모리에서의			" >> $CREATE_FILE 2>&1
echo "		 적절한 한계값 검사를 하지 않는 버퍼 오버플로우 취약점이 존재함 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ DNS 서비스 확인"  >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep -i 'domain|name|dns' | grep -v grep | wc -l` -ge 1 ]; then
		ps -ef | egrep -i 'domain|name' | grep -v grep >> $CREATE_FILE 2>&1
	else
		echo "DNS 서비스 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
#금보원 스크립트에서 확인하는 설정파일
dnscf="/etc/named.boot /etc/named.conf /etc/bind/named.boot /etc/bind/named.conf /etc/bind/named.conf.options"
echo "☞ fake-iquery 설정 확인"  >> $CREATE_FILE 2>&1
for file in $dnscf;
do
	if [ -f $file ]; then
		echo "-------------------------------------------">> $CREATE_FILE 2>&1
		echo $file"파일 설정"  >> $CREATE_FILE 2>&1
		echo "-------------------------------------------">> $CREATE_FILE 2>&1
		cat $file | grep -i 'fake-iquery' >> $CREATE_FILE 2>&1
	else
		echo $file" 파일이 존재하지 않습니다"  >> $CREATE_FILE 2>&1
	fi
done
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-061 END__##>"
echo "<##__SRV-061 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-062 START__##>"
echo "<##__SRV-062 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-062  BIND 서버 버전 노출 여부                                              " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - DNS 서비스의 버전 정보가 외부에 노출되는 경우                    " >> $CREATE_FILE 2>&1  
echo "      취약 - DNS 서비스의 버전 정보가 외부에 노출되지 않는 경우                      " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ DNS 서비스 확인"  >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep -i 'domain|name|dns' | grep -v grep | wc -l` -ge 1 ]; then
		ps -ef | egrep -i 'domain|name' | grep -v grep  >> $CREATE_FILE 2>&1
	else
		echo "DNS 서비스 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "☞ DNS 서버 버전 노출 여부 " >> $CREATE_FILE 2>&1
if [ -f /etc/named.conf ]; then
	cat /etc/named.conf | grep -i 'version' | grep -v '^//' >> $CREATE_FILE 2>&1
else
	echo "/etc/named.conf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-062 END__##>"
echo "<##__SRV-062 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-063 START__##>"
echo "<##__SRV-063 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-063  DNS Recursive Query 설정 미흡                                         " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - DNS Recursive Query 설정에 대해 적절한 보안 설정을 한 경우                  " >> $CREATE_FILE 2>&1  
echo "       취약 - DNS Recursive Query 설정에 대해 보안 설정이 되어 있지 않은 경우       " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ DNS 서비스 확인"  >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep -i 'domain|name|dns' | grep -v grep | wc -l` -ge 1 ]; then
		ps -ef | egrep -i 'domain|name' | grep -v grep >> $CREATE_FILE 2>&1
	else
		echo "DNS 서비스 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "☞ Recursive Query 설정 확인"  >> $CREATE_FILE 2>&1
dnscf="/etc/named.boot /etc/named.conf /etc/bind/named.boot /etc/bind/named.conf /etc/bind/named.conf.options"
for file in $dnscf;
do
	if [ -f $file ]; then
		echo "-------------------------------------------">> $CREATE_FILE 2>&1
		echo "☞ "$file"파일 설정"  >> $CREATE_FILE 2>&1
		cat $file | grep -i 'recursion' >> $CREATE_FILE 2>&1
		echo "-------------------------------------------">> $CREATE_FILE 2>&1
	else
		echo $file" 파일이 존재하지 않습니다"  >> $CREATE_FILE 2>&1
	fi
done
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-063 END__##>"
echo "<##__SRV-063 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-064 START__##>"
echo "<##__SRV-064 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-064 DNS 보안 버전 패치                                                  " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - DNS 보안 패치를 최신 버전으로 유지한 경우                    " >> $CREATE_FILE 2>&1  
echo "      취약 - DNS 보안 패치를 최신버전으로 유지하지 않은 경우               " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " [참고] 최신버전(2016.01 기준 9.10.3-P2) 이하의 버전에서는 서비스거부공격, 버퍼오버플로우 및          " >> $CREATE_FILE 2>&1
echo "       DNS 서버 원격 침입 등의 취약성이 존재함        " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ DNS 서비스 확인"  >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep -i 'domain|name|dns' | grep -v grep | wc -l` -ge 1 ]; then
	ps -ef | egrep -i 'domain|name|dns' | grep -v grep  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "☞ named -v 명령어" >> $CREATE_FILE 2>&1
	named -v >> $CREATE_FILE 2>&1
else
	echo "DNS가 비실행중입니다 " >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-064 END__##>"
echo "<##__SRV-064 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

# YP 의 정식 명칭은 NIS version 2 / NIS+와 구별 짓기 위해 YP(Yellow Page) system 이라는 이름 사용
# Sun Microsystem 에서는 NIS+를 제공하고 있는데, 이는 NIS version 3에 속함
echo "<##__SRV-065 START__##>"
echo "<##__SRV-065 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-065 NIS, NIS+ 점검                                                 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - NIS를 사용하지 않거나, NIS+를 사용할 경우                             " >> $CREATE_FILE 2>&1  
echo "      취약 - NIS를 사용하거나 주기적으로 검사를 하지 않을 경우                        " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ NIS 관련 서비스 구동 여부" >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep 'ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated' | grep -v grep | wc -l` -ge 1 ]; then
	ps -ef | egrep 'ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated' | grep -v grep >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "☞ 설치된 패키지 확인 " >> $CREATE_FILE 2>&1
	rpm -qa | grep ypserv  >> $CREATE_FILE 2>&1
	#rpm -qa | grep nis  >> $CREATE_FILE 2>&1
else
	echo "NIS 서비스가 구동중이지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "[참고] 부팅 스크립트의 run level별 nis 확인" >> $CREATE_FILE 2>&1
if [ `ls -alR /etc/rc*.d | grep yp | wc -l` -eq 0 ]
then
	echo "부팅 스크립트에 NIS, NIS+ 관련 서비스 없음." >> $CREATE_FILE 2>&1
else
	ls -alR /etc/rc*.d | grep yp >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-065 END__##>"
echo "<##__SRV-065 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-066 START__##>"
echo "<##__SRV-066 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-066 DNS ZoneTransfer 설정                                               " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - DNS Zonetransfer를 허가된 사용자에게만 허용한 경우           " >> $CREATE_FILE 2>&1  
echo "      취약 - DNS Zonetransfer를 허가된 사용자 이외에 허용된 경우           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep -i "name|domain" | grep -v grep | wc -l` -eq 0 ]; then
	echo "DNS가 비실행중입니다 " 												>> $CREATE_FILE 2>&1
	echo " "                                   				                >> $CREATE_FILE 2>&1
else
	echo "☞ DNS 실행 여부"	                                  				>> $CREATE_FILE 2>&1
	ps -ef | egrep -i "name|domain" | grep -v grep							>> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	dnscf='/etc/named.conf /etc/named.boot /etc/bind/named.boot /etc/bind/named.conf.options'
	for lists in $dnscf; do
		if [ -f $lists ]; then
			echo "--------------------------------------------------"	        >> $CREATE_FILE 2>&1
			echo $lists" 파일의 allow-transfer 확인"	                            >> $CREATE_FILE 2>&1	
			cat $lists | egrep -i 'allow-transfer|xfrnets'                  >> $CREATE_FILE 2>&1
			echo "--------------------------------------------------"	        >> $CREATE_FILE 2>&1
		else
			echo $lists" 파일이 존재하지 않습니다."   							>> $CREATE_FILE 2>&1
		fi
	done
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-066 END__##>"
echo "<##__SRV-066 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-069 START__##>"
echo "<##__SRV-069 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-069  비밀번호 관리정책  점검                                             "				   >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 비밀번호 관리정책이 설정되어 있는 경우                           " 				   >> $CREATE_FILE 2>&1  
echo "      취약 - 비밀번호 관리정책이 설정되어 있지 않은 경우                           " 			   >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "[참고] dcredit=최소숫자, ucredit=최소대문자, lcredit=최소소문자, ocredit=최소특수문자 " >> $CREATE_FILE 2>&1
echo "      minlen=패스워드 최소갯수, difok=기존 패스워드와 비교(기본값 10(50%)) " >> $CREATE_FILE 2>&1
echo "      PASS_MAX_DAYS : 패스워드 최대 사용 기간, PASS_MIN_DAYS : 패스워드 최소 사용 기간  " >> $CREATE_FILE 2>&1
echo "      PASS_MIN_LEN : 패스워드 최소 길이, PASS_WARN_AGE : 패스워드 만료 전 경고 메시지 표시 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "--------------------------------------------------"	        >> $CREATE_FILE 2>&1
echo "/etc/login.defs 파일 설정 "	                         	    >> $CREATE_FILE 2>&1	
echo "--------------------------------------------------"	        >> $CREATE_FILE 2>&1
if [ -f /etc/login.defs ]; then
	cat /etc/login.defs | egrep -i 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE' | grep -v '^#'	        >> $CREATE_FILE 2>&1
else
	echo "/etc/login.defs 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "--------------------------------------------------"	        >> $CREATE_FILE 2>&1
echo "/etc/pam.d/system-auth 파일 설정(RHEL5/6)"	                    >> $CREATE_FILE 2>&1	
echo "--------------------------------------------------"	        >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/system-auth ]; then
	if [ `cat /etc/pam.d/system-auth | egrep -i 'minlen|minclass|maxrepeat|maxclassrepeat|lcredit|ucredit|dcredit|ocredit' | wc -l` -eq 0 ]; then
		echo "비밀번호 관련 설정이 존재하지 않습니다."	>> $CREATE_FILE 2>&1
	else
		cat /etc/pam.d/system-auth | egrep -i 'minlen|minclass|maxrepeat|maxclassrepeat|lcredit|ucredit|dcredit|ocredit'	>> $CREATE_FILE 2>&1
	fi
else	
	echo "/etc/pam.d/system-auth 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "--------------------------------------------------"	        >> $CREATE_FILE 2>&1
echo "/etc/security/pwquality.conf 파일 설정(RHEL7)"	                         	    >> $CREATE_FILE 2>&1	
echo "--------------------------------------------------"	        >> $CREATE_FILE 2>&1
if [ -f /etc/security/pwquality.conf ]; then
	cat /etc/security/pwquality.conf | egrep -i 'minlen|minclass|maxrepeat|maxclassrepeat|lcredit|ucredit|dcredit|ocredit' 	        >> $CREATE_FILE 2>&1
else
	echo "/etc/security/pwquality.conf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-069 END__##>"
echo "<##__SRV-069 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-070 START__##>"
echo "<##__SRV-070 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-070  비밀번호 저장파일 보호                                                  " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - /etc/shadow 파일에 패스워드를 저장 할 경우              " >> $CREATE_FILE 2>&1  
echo "      취약 - /etc/passwd 파일에 패스워드를 저장 할 경우              " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ shadow 파일 확인" >> $CREATE_FILE 2>&1
if [ -f /etc/shadow ]; then
	ls -al /etc/shadow >> $CREATE_FILE 2>&1
	else
	echo "/etc/shadow 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "☞ passwd 파일 내 두번째 필드 x 표시 확인(계정명 : 두번째필드)" >> $CREATE_FILE 2>&1
awk -F: '{print $1,":",$2}' /etc/passwd >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-070 END__##>"
echo "<##__SRV-070 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-073 START__##>"
echo "<##__SRV-073 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-073 관리자 그룹에 최소한의 계정 포함                                    " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 관리자 그룹에 불필요한 계정이 존재하지 않을 경우             " >> $CREATE_FILE 2>&1  
echo "      취약 - 관리자 그룹에 불필요한 계정이 존재 할 경우                   " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "[1] /etc/passwd 파일에서 관리자계정" >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
    awk -F: '$3==0 {print $1,": UID=",$3," , GID=",$4}' /etc/passwd      >> $CREATE_FILE 2>&1
  else
    echo "/etc/passwd 파일이 없습니다."                                                        >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "[2] /etc/group파일에서 관리자 그룹(GID=0)" >> $CREATE_FILE 2>&1
awk -F: '$3==0' /etc/group  >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-073 END__##>"
echo "<##__SRV-073 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "<##__SRV-074 START__##>"
echo "<##__SRV-074 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-074  관리되지 않는 계정 및 비밀번호 점검                                           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 기본 계정 및 시스템 사용이 만료된 사용자 계정 등 불필요한 계정이         " >> $CREATE_FILE 2>&1  
echo "            존재하거나 장기간 변경하지 않는 비밀번호가 존재할 경우                   " >> $CREATE_FILE 2>&1
echo "      취소 - 기본 계정 및 시스템 사용이 만료된 사용자 계정 등 불필요한 계정이         " >> $CREATE_FILE 2>&1  
echo "            존재하지 않으며 장기간 변경하지 않는 비밀번호가 존재하지 않은 경우       " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo "[1] 불필요한 계정 확인" >> $CREATE_FILE 2>&1
cat /etc/passwd >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "[2] 패스워드 마지막 변경일 확인" >> $CREATE_FILE 2>&1
awk -F: '{print $1}' /etc/passwd >> nname.txt
while read line
do
	echo "☞ "$line" 계정" >> $CREATE_FILE 2>&1
	chage -l $line>> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
done < nname.txt
rm -rf nname.txt
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-074 END__##>"
echo "<##__SRV-074 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-075 START__##>"
echo "<##__SRV-075 START__##>"	>> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-075  유추가능한 비밀번호 사용 여부                                          " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 문자/숫자/특수문자를 모두 포함될 수있도록 암호 복잡성을 설정한 경우        " >> $CREATE_FILE 2>&1
echo "            회사에서 정한 비밀번호 관리정책을 준수하고 있는 경우     " >> $CREATE_FILE 2>&1   
echo "      취소 - 암호 복잡성이 설정되어 있지 않고 암호가 간단하게 설정되어 있는 경우        " >> $CREATE_FILE 2>&1  
echo "            회사에서 정한 비밀번호 관리정책을 준수하고 있지 않는 경우     " >> $CREATE_FILE 2>&1  
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "[참고] dcredit=최소숫자, ucredit=최소대문자, lcredit=최소소문자, ocredit=최소특수문자 " >> $CREATE_FILE 2>&1
echo "      minlen=패스워드 최소갯수, difok=기존 패스워드와 비교(기본값 10(50%)) " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "--------------------------------------------------"	        >> $CREATE_FILE 2>&1
echo "/etc/pam.d/system-auth 파일 설정(RHEL5/6)"	                         	    >> $CREATE_FILE 2>&1	
echo "--------------------------------------------------"	        >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/system-auth ]; then
	cat /etc/pam.d/system-auth | egrep -i 'minlen|minclass|maxrepeat|maxclassrepeat|lcredit|ucredit|dcredit|ocredit' 	        >> $CREATE_FILE 2>&1
else
	echo "/etc/pam.d/system-auth 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "--------------------------------------------------"	        >> $CREATE_FILE 2>&1
echo "/etc/security/pwquality.conf 파일 설정(RHEL7)"	                         	    >> $CREATE_FILE 2>&1	
echo "--------------------------------------------------"	        >> $CREATE_FILE 2>&1
if [ -f /etc/security/pwquality.conf ]; then
	cat /etc/security/pwquality.conf | egrep -i 'minlen|minclass|maxrepeat|maxclassrepeat|lcredit|ucredit|dcredit|ocredit' 	        >> $CREATE_FILE 2>&1
else
	echo "/etc/security/pwquality.conf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-075 END__##>"
echo "<##__SRV-075 END__##>"	>> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-081 START__##>"
echo "<##__SRV-081 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-081  Crontab 설정파일 권한 설정 오류                                           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - Others 권한에 쓰기 및 읽기 권한이 부여되지 않은 경우      " >> $CREATE_FILE 2>&1  
echo "■     취소 - Others 권한에 쓰기 및 읽기 권한이 부여되어 있는 경우        " >> $CREATE_FILE 2>&1  
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
cronconf="/var/spool/cron /var/spool/cron/crontabs"
for list in $cronconf; do
	echo "☞ "$list" 디렉토리" >> $CREATE_FILE 2>&1
if [ -d $list ]; then
	ls -alL $list							>> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
else
	echo $list" 디렉토리가 존재하지 않습니다." >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
fi
done
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-081 END__##>"
echo "<##__SRV-081 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-082 START__##>"
echo "<##__SRV-082 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-082  시스템 디렉토리 권한설정 미비                                           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 시스템 디렉토리 권한이 적절하게 설정되어 있는 경우      " >> $CREATE_FILE 2>&1  
echo "■     취소 - 시스템 디렉토리 권한이 적절하지 않은 경우        " >> $CREATE_FILE 2>&1  
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
sysdir="/usr /bin /sbin /etc /var"
for list in $sysdir
do
	if [ -d $list ]; then
		ls -alLd $list							>> $CREATE_FILE 2>&1
	else
		echo $list" 디렉토리가 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi
done
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-082 END__##>"
echo "<##__SRV-082 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-083 START__##>"
echo "<##__SRV-083 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-083  시스템 스타트업 스크립트 권한 설정 오류                                           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 시스템 스타트업 스크립트 권한이 적절하게 설정되어 있는 경우      " >> $CREATE_FILE 2>&1  
echo "■      취소 - 시스템 스타트업 스크립트 권한이 적절하지 않은 경우        " >> $CREATE_FILE 2>&1  
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "스타트업 스크립트 파일" >> $CREATE_FILE 2>&1
echo "------------------------------------------------------" >> $CREATE_FILE 2>&1
DIR_STARTUP="/etc/init.d /etc/rc2.d /etc/rc3.d /etc/rc.d/init.d /etc/rc.d/rc2.d /etc/rc.d/rc3.d"
for list in $DIR_STARTUP
do
	if [ -d $list ]; then
		echo "☞ "$list "디렉토리" >> $CREATE_FILE 2>&1
		ls -alLd $list/*						>> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo $list" 디렉토리가 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi
done
echo "------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "/etc/inittab에 설정된 파일" >> $CREATE_FILE 2>&1
echo "------------------------------------------------------" >> $CREATE_FILE 2>&1
if [ `cat /etc/inittab | grep -v '^#' | wc -l` -eq 0 ]; then
	echo '/etc/inittab에 설정된 파일이 없습니다.' >> $CREATE_FILE 2>&1
else
	startup=`cat /etc/inittab | grep -v "^#"  | awk -F: '{print $4}' | awk -F' ' '{print $1}'`
	for list in $startup
	do
		if [ -f $list ]; then
			echo "☞ "$list "파일" >> $CREATE_FILE 2>&1
			ls -alLd $list						>> $CREATE_FILE 2>&1
			echo " " >> $CREATE_FILE 2>&1
		else
			echo $list" 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi	
	done
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-083 END__##>"
echo "<##__SRV-083 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-084 START__##>"
echo "<##__SRV-084 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-084  /etc/passwd 파일 및 디렉터리 소유자 설정                            " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - passwd 파일의 권한이 644 이하, 소유자가 root인 경우          " >> $CREATE_FILE 2>&1  
echo "      취약 - passwd 파일의 권한이 644 초과, 소유자가 root가 아닌 경우     " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]; then
	ls -alL /etc/passwd >> $CREATE_FILE 2>&1
else
	echo "/etc/passwd 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-084 END__##>"
echo "<##__SRV-084 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-085 START__##>"
echo "<##__SRV-085 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-085  /etc/shadow 파일 소유자 및 권한 설정                                " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - shadow 파일의 권한이 400 이하, 소유자가 root인 경우          " >> $CREATE_FILE 2>&1  
echo "      취약 - shadow 파일의 권한이 400 초과, 소유자가 root가 아닌 경우     " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/shadow ]; then
	ls -alL /etc/shadow >> $CREATE_FILE 2>&1 
else
	echo "/etc/shadow 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-085 END__##>"
echo "<##__SRV-085 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-086 START__##>"
echo "<##__SRV-086 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-086  /etc/hosts 파일 소유자 및 권한 설정                                 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - hosts 파일의 권한이 644 미만, 소유자가 root인 경우           " >> $CREATE_FILE 2>&1  
echo "      취약 - hosts 파일의 권한이 644 이상, 소유자가 root가 아닌 경우      " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/hosts ]; then
	ls -alL /etc/hosts >> $CREATE_FILE 2>&1 
else
	echo "/etc/hosts 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-086 END__##>"
echo "<##__SRV-086 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-087 START__##>"
echo "<##__SRV-087 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-087  C 컴파일러 존재 및 권한 설정 오류                                 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 필요한 C 컴파일러만 존재하며 권한 설정이 적절한 경우           " >> $CREATE_FILE 2>&1  
echo "      취약 - 필요하지 않은 C컴파일러가 존재하거나 권한 설정이 적절하지 않은 경우      " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
Ccomfile='/usr/bin/cc /usr/bin/gcc /usr/ucb/cc /usr/ccs/bin/cc /opt/ansic/bin/cc /usr/vac/bin/cc /usr/local/bin/gcc'
for list in $Ccomfile;
do
	if [ -f $list ]; then
		ls -al $list  >> $CREATE_FILE 2>&1
	else
		echo $list" 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
	fi
done
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "[참고] which 명령어로 확인" >> $CREATE_FILE 2>&1
hfiles=`which cc`  >> $CREATE_FILE 2>&1
for hfile in $hfiles; do
	if [ $hfile = 'no' -o $hfile = "which:" ]; then
		echo $hfiles >> $CREATE_FILE 2>&1
		break
	fi
	ls -alL $hfile >> $CREATE_FILE 2>&1
	hsym=`ls -alL $hfile | awk '{print $q}' | grep "[a-zA-Z0-9]"`
		if [ `echo $hsym | cut -c1-1` = "l" ]; then
			hsym_=`ls -alL $hfile | awk '{print $11}' | grep "[a-zA-Z0-9]"`
			if [ `echo $hsym_ | cut -c1-2` = ".." ]; then
				hsym1=`ls -alL $hfile | awk '{print $9}'`
				hsym2=`ls -alL $hfile | awk '{print $11}'`
				ls -alL "$hsym1$hsym2"  >> $CREATE_FILE 2>&1
			else
				hsymorg=`ls -alL $hfile | awk '{print $11}' | grep "[a-zA-Z0-9]"`
				ls -alL $hsymorg  >> $CREATE_FILE 2>&1
			fi
		fi
done
echo " " >> $CREATE_FILE 2>&1
hfiles=`which gcc`  >> $CREATE_FILE 2>&1
for hfile in $hfiles; do
	if [ $hfile = "no" -o $hfile = "which:" ]; then
		echo $hfiles  >> $CREATE_FILE 2>&1
		break
	fi
	ls -alL $hfile echo " " >> $CREATE_FILE 2>&1
	hsym=`ls -alL $hfile | awk '{print $1}' | grep "[a-zA-Z0-9]"`
	if [ `echo $hsym | cut -c1-1` = "l" ]; then
		hsymorg=`ls -alL $hfile | awk '{print $11}' | grep "[a-zA-Z0-9]"`
		ls -alL $hsymorg  >> $CREATE_FILE 2>&1
	fi
done
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-087 END__##>"
echo "<##__SRV-087 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-088 START__##>"
echo "<##__SRV-088 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-088  /etc/[x]inetd.conf 파일 소유자 및 권한 설정                         " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - [x]inetd.conf 파일의 권한600이하, 소유자가 root인 경우       " >> $CREATE_FILE 2>&1  
echo "      취약 - [x]inetd.conf 파일의 권한600초과, 소유자가 root가 아닌 경우  " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "[1] inetd.conf 파일 " >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]; then
	ls -alL /etc/inetd.conf >> $CREATE_FILE 2>&1 
else
	echo "/etc/inetd.conf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "[2] xinetd.d 디렉토리 및 xinetd.conf 파일 " >> $CREATE_FILE 2>&1
if [ -f /etc/xinetd.conf ]; then
	ls -alL /etc/xinetd.conf >> $CREATE_FILE 2>&1
else
	echo "/etc/xinetd.conf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
if [ -d /etc/xinetd.d ]; then
	echo "☞ /etc/xinetd.d 디렉토리 이하" >> $CREATE_FILE 2>&1
	ls -alL /etc/xinetd.d >> $CREATE_FILE 2>&1
else
	echo "/etc/xinetd.d 디렉토리가 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-088 END__##>"
echo "<##__SRV-088 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-089 START__##>"
echo "<##__SRV-089 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-089  /etc/syslog.conf 파일 소유자 및 권한 설정                           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - syslog.conf 파일의 권한 644이하, 소유자가 root(또는 bin, sys)인 경우    " >> $CREATE_FILE 2>&1  
echo "      취약 - syslog.conf 파일의 권한 644초과, 소유자가 root(또는 bin, sys)가 아닌 경우 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
sysconf='/etc/syslog.conf /etc/rsyslog.conf'
for list in $sysconf;
do
if [ -f $list ]; then
	ls -alL $list >> $CREATE_FILE 2>&1
else
	echo $list" 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
done
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-089 END__##>"
echo "<##__SRV-089 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-091 START__##>"
echo "<##__SRV-091 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-091  SUID, SGID, Sticky bit 설정 파일 점검                               " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 필요한 파일에 SUID, SGID, Sticky bit 설정이 된 경우          " >> $CREATE_FILE 2>&1  
echo "      취약 - 불필요한 파일에 SUID, SGID, Sticky bit 설정이 된 경우        " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "참고 [LINUX 제거 항목]                                                         " >> $CREATE_FILE 2>&1
echo "     /sbin/dump /sbin/restore /sbin/unix_chkpwd /usr/bin/at      " >> $CREATE_FILE 2>&1
echo "     /usr/bin/lpq /usr/bin/lpq-lpd /usr/bin/lpr /usr/bin/lpr-lpd " >> $CREATE_FILE 2>&1
echo "     /usr/bin/lprm /usr/bin/lprm-lpd /usr/sbin/traceroute " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIR=`cat /etc/passwd | egrep -v ":nosh" | grep "sh$" | awk -F":" '{print $6}' | sort -u`
FILE_SETUID='/sbin/dump /sbin/restore /sbin/unix_chkpwd /usr/bin/at /usr/bin/lpq /usr/bin/lpq-lpd /usr/bin/lpr /usr/bin/lpr-lpd /usr/bin/lprm /usr/bin/lprm-lpd /usr/sbin/traceroute'
TMP_HOMEDIR=""
for dir in $HOMEDIR
	do
		if [ $dir != "/" -a $dir != "/root" -a -d $dir ]; then
			TMP_HOMEDIR=`echo $TMP_HOMEDIR" "``echo $dir`;
		fi
	done
nice -n 5 find $TMP_HOMEDIR -type f -a -perm -4000 -exec ls -alLd {} \; 2>/dev/null >> $CREATE_FILE 2>&1
for hfile in $FILE_SETUID; do
	if [ -f $hfile ]; then
		ls -alL $hfile >> $CREATE_FILE 2>&1
	fi
done
echo "<##__SRV-091 END__##>"
echo "<##__SRV-091 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-092 START__##>"
echo "<##__SRV-092 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-092 홈디렉토리 소유자 및 권한 설정                                      " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 해당 계정이 홈 디렉토리를 소유한 경우  " >> $CREATE_FILE 2>&1  
echo "            해당 계정만이 홈 디렉토리에 대한 모든 권한을 소유하도록 설정된 경우 " >> $CREATE_FILE 2>&1
echo "      취약 - 타 사용자 또는 존재하지 않는 사용자가 홈 디렉토리를 소유한 경우 " >> $CREATE_FILE 2>&1
echo "            해당 사용자 이외의 계정이 홈 디렉토리에 대한 모든 권한을 소유하도록 설정된 경우 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "계정 별 홈디렉터리의 권한" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
homedir=`cat /etc/passwd | awk -F':' '{print $1","$6}'`
for dir1 in $homedir
do
id=`echo $dir1 | awk -F"," '{print $1}'`
pwd=`echo $dir1 | awk -F"," '{print $2}'`
echo $id 				>> $CREATE_FILE 2>&1 
if [ -d $pwd ] ; 
	then
		ls -dl $pwd 				>> $CREATE_FILE 2>&1
	else
		echo $pwd" 디렉토리가 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
done
echo "--------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "홈디렉토리가 존재하지 않는 계정 확인" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
for dir in $HOMEDIRS
do
	if [ ! -d $dir ]
		then
			cat /etc/passwd | awk -F":" '$6=="'${dir}'" { print $1" 계정의 홈디렉토리(" $6 ")가 존재하지 않습니다" }' >> homelist.txt
	fi
done
if [ -f homelist.txt ] ;
	then 
		cat homelist.txt >> $CREATE_FILE 2>&1
	else 
		echo "홈 디렉터리가 존재하지 않는 계정이 없습니다." >> $CREATE_FILE 2>&1
fi
rm -rf homelist.txt
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-092 END__##>"
echo "<##__SRV-092 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-093 START__##>"
echo "<##__SRV-093 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-093 world writable 파일 점검                                            " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 불필요한 world writable 파일이 존재하지 않을 경우            " >> $CREATE_FILE 2>&1  
echo "      취약 - 불필요한 world writable 파일이 존재할 경우                   " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
#금보원 스크립트 반영
HOMEDIR=`cat /etc/passwd | egrep -v ":nosh" | grep "sh$" | awk -F":" '{print $6}' | sort -u`
for dir in $HOMEDIR
do
	if [ $dir != "/" -a $dir != "/root" -a -d $dir ]; then
		TMP_HOMEDIR=`echo $TMP_HOMEDIR" "``echo $dir`;
	fi
done
nice -n 5 find $TMP_HOMEDIR -perm -2 -type f -exec ls -alL {} \; 2>/dev/null | egrep '\.sh|\.log|\.pl' >> wwf.txt
if [ `cat wwf.txt | wc -l` -eq 0 ]; then
	echo "world writable 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
else
	cat wwf.txt >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
rm -rf wwf.txt
echo "<##__SRV-093 END__##>"
echo "<##__SRV-093 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-094 START__##>"
echo "<##__SRV-094 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-094  Crontab 참조파일 권한 설정 오류                           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - Crontab의 작업 설정 파일의 others 권한에 쓰기 권한이 없는 경우    " >> $CREATE_FILE 2>&1  
echo "      취약 - Crontab의 작업 설정 파일의 others 권한에 쓰기 권한이 있는 경우 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "■ 결과 값이 없는 경우 others 권한에 쓰기 권한이 존재하지 않으므로 양호함" >> $CREATE_FILE 2>&1
if [ -d /var/spool/cron/crontabs/ ]; then
	REFLIST=`cat /var/spool/cron/crontabs/* | egrep ".sh|.pl" | awk '{print $6}' `
else
	REFLIST=`cat /var/spool/cron/* | egrep ".sh|.pl" | awk '{print $6}' `
fi
for file in $REFLIST
do
	if [ -f $file ]; then
		ls -alL $file | awk '{print $1 " : " $NF}' >> $CREATE_FILE 2>&1
	fi
done
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-094 END__##>"
echo "<##__SRV-094 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-095 START__##>"
echo "<##__SRV-095 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-095  파일 및 디렉터리 소유자 설정                                        " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 소유자가 존재하지 않는 파일이 존재하지 않을 경우             " >> $CREATE_FILE 2>&1  
echo "      취약 - 소유자가 존재하지 않는 파일이 존재하는 경우                        " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "(/ 이외의 홈 디렉터리 이하 파일 중 검색)" >> $CREATE_FILE 2>&1
HOMEDIR=`cat /etc/passwd | egrep -v ":nosh" | grep "sh$" | awk -F":" '{print $6}' | sort -u`
TMP_HOMEDIR=""
for dir in $HOMEDIR
do
	if [ $dir != "/" -a $dir != "/root" -a -d $dir ]; then
		TMP_HOMEDIR=`echo $TMP_HOMEDIR" "``echo $dir`;
	fi
done
nice -n 5 find $TMP_HOMEDIR -type f -a -nouser -nogroup -exec ls -alLd {} \; 2>/dev/null >> nouser.txt
if [ `cat nouser.txt | wc -l` -eq 0 ]; then
	echo "소유자가 존재하지 않는 디렉토리 및 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
else
	cat nouser.txt >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
rm -rf nouser.txt
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-095 END__##>"
echo "<##__SRV-095 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-096 START__##>"
echo "<##__SRV-096 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-096 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정             " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 환경파일이 변경되지 않았거나, root와 소유자만 write 가능한 경우  " >> $CREATE_FILE 2>&1  
echo "      취약 - 환경파일이 변경되었거나, root와 소유자 이외에도 write 가능한 경우 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "-----------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "/etc/profile 소유자 및 권한 " >> $CREATE_FILE 2>&1
echo "-----------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]; 
	then
		ls -al /etc/profile >> $CREATE_FILE 2>&1
	else
		echo "/etc/profile 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "-----------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "홈디렉터리 별 환경변수 파일 소유자 및 권한 " >> $CREATE_FILE 2>&1
echo "-----------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F: '{print $6}' | sort -u`
for dir in $HOMEDIR
do
if [ -f $dir ]; then
	if [ $dir != "/" -a $dir != "/root" ]; then
		hfiles=`ls -alL $dir | awk -F" " '{print $9}' | grep "^[.][a-zA-Z0-9]"`
			for hfile in $hfiles; do
				ls -aldL $dir/$hfile >> $CREATE_FILE 2>&1
			done
	fi	
fi
done
echo " " >> $CREATE_FILE 2>&1
echo "-----------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "root 디렉터리 환경변수 파일 소유자 및 권한 " >> $CREATE_FILE 2>&1
echo "-----------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
hfiles=`ls -alL /root | awk -F" " '{print $9}' | grep "^[.][a-zA-Z0-9]"`
for hfile in $hfiles; do
	ls -aldL /root/$hfile >> $CREATE_FILE 2>&1
done
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-096 END__##>"
echo "<##__SRV-096 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-099 START__##>"
echo "<##__SRV-099 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-099  /etc/services 파일 소유자 및 권한 설정                              " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - services 파일의 권한 644이하, 소유자가 root(또는 bin, sys)인 경우     " >> $CREATE_FILE 2>&1  
echo "      취약 - services 파일의 권한 644초과, 소유자가 root(또는 bin, sys)가 아닌 경우  " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/services ]; then
ls -alL /etc/services >> $CREATE_FILE 2>&1 
else
	echo "/etc/services 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-099 END__##>"
echo "<##__SRV-099 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-100 START__##>"
echo "<##__SRV-100 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-100 xterm 실행 파일 권한 설정                                  " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - xterm 실행 파일의 권한이 적절하게 설정되어 있는 경우               " >> $CREATE_FILE 2>&1  
echo "      취약 - xterm 실행 파일의 권한이 적절하지 않은 경우      " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
PathXterm=`which xterm`
if [ $PathXterm = "no" -o $PathXterm = "which:" ]; then
	echo "xterm 실행파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	which xterm >> $CREATE_FILE 2>&1
else
	ls -aldL $PathXterm >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-100 END__##>"
echo "<##__SRV-100 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-106 START__##>"
echo "<##__SRV-106 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-106 hosts.lpd 파일 소유자 및 권한 설정                                  " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - hosts.lpd 파일권한 600이하, 소유자 root인 경우               " >> $CREATE_FILE 2>&1  
echo "      취약 - hosts.lpd 파일권한 600초과, 소유자가 root가 아닌 경우        " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/hosts.lpd ]
then
	ls -alL /etc/hosts.lpd >> $CREATE_FILE 2>&1             
else
	echo "/etc/hosts.lpd 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-106 END__##>"
echo "<##__SRV-106 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-107 START__##>"
echo "<##__SRV-107 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-107 at 접근제한 파일 소유자 및 권한 설정                                         " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - at파일 권한 640 이하, 소유자 root일 경우                     " >> $CREATE_FILE 2>&1  
echo "       취약 - at파일 권한 640 초과, 소유자 root가 아닐 경우                " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ at.allow 파일 " >> $CREATE_FILE 2>&1
if [ -f /etc/at.allow ];
then
	ls -al /etc/at.allow                                                              >> $CREATE_FILE 2>&1
else
	echo "/etc/at.allow 파일이 없습니다."                                               >> $CREATE_FILE 2>&1
fi
echo " "                                                    >> $CREATE_FILE 2>&1
echo "☞ at.deny 파일 " >> $CREATE_FILE 2>&1
if [ -f /etc/at.deny ];
then
	ls -al /etc/at.deny                                                              >> $CREATE_FILE 2>&1
else
	echo "/etc/at.deny 파일이 없습니다."                                                >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-107 END__##>"
echo "<##__SRV-107 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-108 START__##>"
echo "<##__SRV-108 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-108 과도한 시스템 로그파일 권한 설정                                         " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 로그 파일의 권한이 적절하게 설정된 경우                     " >> $CREATE_FILE 2>&1  
echo "      취약 - 로그 파일의 권한이 적절하게 설정되지 않은 경우            " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
#금보원 스크립트에서 확인하는 디렉토리(linux는 /var/log)만 출력
DIR_LOG="/var/log"
for ldir in $DIR_LOG; do
	echo "☞ "$ldir" 디렉터리"	>> $CREATE_FILE 2>&1
	ls -aldL $ldir/*	>> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
done
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-108 END__##>"
echo "<##__SRV-108 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-115 START__##>"
echo "<##__SRV-115 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-115  로그의 정기적 검토 및 보고                                          " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 정기적으로 로그에 대한 검토 및 보고가 이루어지는 경우  " >> $CREATE_FILE 2>&1  
echo "      취약 - 정기적으로 로그에 대한 검토 및 보고가 이루어지지 않는 경우 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "참고 *.emerg;*alert;*.crit;*.err;*.warning;*.notice;*.info               " >> $CREATE_FILE 2>&1  
echo "     wtmpx, utmpx, wtmp, utmp, syslog, sulog, pacct                     " >> $CREATE_FILE 2>&1  
echo "     authlog, messages, loinlog, lastlog                                " >> $CREATE_FILE 2>&1  
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "담장자 인터뷰 필요"          >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-115 END__##>"
echo "<##__SRV-115 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-118 START__##>"
echo "<##__SRV-118 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-118  최신 보안패치 및 벤더 권고사항 적용                                 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 패치 적용 정책을 수립하여 주기적으로 패치 관리하는 경우      " >> $CREATE_FILE 2>&1  
echo "            지속적인 패치가 이루어지고 있는 경우 " >> $CREATE_FILE 2>&1
echo "            (Linux는 서버에 설치된 패치 리스트의 관리가 불가능하므로 양호) " >> $CREATE_FILE 2>&1
echo "      취약 - 패치 적용 정책을 수립하여 주기적으로 패치 관리하지 않는 경우 " >> $CREATE_FILE 2>&1
echo "            지속적인 패치가 이루어지고 있지 않은 경우 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ OS 정보 확인" >> $CREATE_FILE 2>&1
uname -a 											>> $CREATE_FILE 2>&1
echo " "		>> $CREATE_FILE 2>&1
echo "☞ version 확인" >> $CREATE_FILE 2>&1
cat /proc/version >> $CREATE_FILE 2>&1
echo " "	                                    	>> $CREATE_FILE 2>&1
echo "☞ 설치된 패키지 및 업데이트 목록 확인" >> $CREATE_FILE 2>&1
yum check-update >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-118 END__##>"
echo "<##__SRV-118 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-121 START__##>"
echo "<##__SRV-121 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-121  root 홈, 패스 디렉터리 권한 및 패스 설정                            " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - path 경로 중 .나 :: 또는 알 수 없는 디렉토리 포함되지 않은  경우       " >> $CREATE_FILE 2>&1  
echo "       취약 - path 경로 중 .나 :: 또는 알 수 없는 디렉토리 포함된 경우       " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
env | grep -i "^path"	>> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "[ 참고 : cat /etc/PATH ]" >> $CREATE_FILE 2>&1
if [ -f /etc/PATH ]; then
	cat /etc/PATH  >> $CREATE_FILE 2>&1
else
	echo "/etc/PATH 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-121 END__##>"
echo "<##__SRV-121 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-122 START__##>"
echo "<##__SRV-122 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-122 UMASK 설정 관리                                                     " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - UMASK 설정이 0022로 설정된 경우                              " >> $CREATE_FILE 2>&1  
echo "       취약 - UMASK 설정이 0022가 아닌 경우                                " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
umask >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-122 END__##>"
echo "<##__SRV-122 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-127 START__##>"
echo "<##__SRV-127 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-127  계정 잠금 임계값 설정                                               " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 계정 사용가능 시간 설정/잠금 시간 설정 등 각종 로그인 관련한 임계값이 설정된 경우 " >> $CREATE_FILE 2>&1  
echo "      취약 - 계정 사용가능 시간 설정/잠금 시간 설정 등 각종 로그인 관련한 임계값이 설정되지 않은 경우 " >> $CREATE_FILE 2>&1  
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " [참고] ex 1) : auth required pam_tally.so deny=4 no_magic_root " >> $CREATE_FILE 2>&1
echo "               account required pam_tally.so no_magic_root reset " >> $CREATE_FILE 2>&1
echo "       ex 2) : auth required pam_tally2.so onerr=fail deny=4 even_deny_root" >> $CREATE_FILE 2>&1
echo "               account required pam_tally2.so even_deny_root reset" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "-----------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "/etc/login.defs 설정" >> $CREATE_FILE 2>&1
echo "-----------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
if [ -f /etc/login.defs ]; then
	cat /etc/login.defs | egrep -i 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE' | grep -v '^#'	        >> $CREATE_FILE 2>&1
else
	echo "/etc/login.defs 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "-----------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "PAM 설정" >> $CREATE_FILE 2>&1
echo "-----------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "☞ /etc/pam.d/system-auth 파일" >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/system-auth  ]; then
	if [ `cat /etc/pam.d/system-auth | grep pam_tally | grep -v "#" | wc -l` -ge 1 ]; then 
		cat /etc/pam.d/system-auth | grep pam_tally | grep -v "#" >> $CREATE_FILE 2>&1
	else 
		cat /etc/pam.d/system-auth  >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/pam.d/system-auth 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "☞ /etc/pam.d/common-password 파일" >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/common-password ]; then
	if [ `cat /etc/pam.d/common-password | grep pam_tally2 | grep -v "#" | wc -l` -ge 1 ]; then 
		cat /etc/pam.d/common-password | grep pam_tally2 >> $CREATE_FILE 2>&1
	else 
		cat /etc/pam.d/common-password  >> $CREATE_FILE 2>&1
	fi
else
	echo "cat /etc/pam.d/common-password  파일이 존재하지 않습니다.">> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-127 END__##>"
echo "<##__SRV-127 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-131 START__##>"
echo "<##__SRV-131 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-131  root 계정 su 제한                                                   " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 지정된 그룹을 설정하여 그룹 사용자에게만 su 명령어를 허가하는 경우(4750퍼미션)" >> $CREATE_FILE 2>&1  
echo "      취약 - su 명령어를 사용할 수 있는 계정이 제한되지 않은 경우       " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "[1] su 사용권한"                                                                          >> $CREATE_FILE 2>&1
if [ -f /usr/bin/su ]
  then
    ls -alL /usr/bin/su >> $CREATE_FILE 2>&1 
  else
    echo " /usr/bin/su 파일 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "[2] su 명령그룹 확인(/etc/group 파일)"                           >> $CREATE_FILE 2>&1
sugr=`ls -al /usr/bin/su | awk '{print $4}'`
cat /etc/group | grep $sugr >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "================================================="   >> $CREATE_FILE 2>&1
echo "PAM 모듈 사용 시"                           >> $CREATE_FILE 2>&1
echo "================================================="   >> $CREATE_FILE 2>&1
echo "☞ /etc/pam.d/su 파일"   >> $CREATE_FILE 2>&1
cat /etc/pam.d/su | grep -v '^#'  >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ wheel 그룹 확인 "   >> $CREATE_FILE 2>&1
if [ `cat /etc/group | grep wheel | wc -l` -eq 0 ]; then 
	echo "wheel 그룹이 존재하지 않습니다." >> $CREATE_FILE 2>&1
else
	cat /etc/group | grep wheel >> $CREATE_FILE 2>&1
fi
echo "================================================="   >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "[참고] /etc/group 파일 " >> $CREATE_FILE 2>&1
cat /etc/group >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-131 END__##>"
echo "<##__SRV-131 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-132 START__##>"
echo "<##__SRV-132 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-132  cron 파일 소유자 및 권한 설정                                       " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - cron 파일 권한 640 이며, 소유자가 root인 경우                " >> $CREATE_FILE 2>&1  
echo "            [cron.allow, deny 파일이 없는경우 root만 사용가능]           " >> $CREATE_FILE 2>&1
echo "      취약 - cron 파일 권한 640 이며, 소유자가 root가 아닌 경우           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
FILE_CRONUSER="/etc/cron.d/cron.allow /etc/cron.d/cron.deny /etc/cron.allow /etc/cron.deny"
for list in $FILE_CRONUSER; do
	echo " " >> $CREATE_FILE 2>&1
	echo "☞ "$list" 파일" >> $CREATE_FILE 2>&1
	if [ -f $list ]; then
		ls -aldL $list							>> $CREATE_FILE 2>&1
	else
		echo $list" 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi
done
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-132 END__##>"
echo "<##__SRV-132 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-133 START__##>"
echo "<##__SRV-133 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-133  cron 파일 내 계정 미존재                                       " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - cron 파일 내 적절한 계정이 설정이 되어 있는 경우                " >> $CREATE_FILE 2>&1  
echo "      취약 - cron 파일 내 적절한 계정이 설정이 되어 있지 않은 경우           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
FILE_CRONUSER="/etc/cron.d/cron.allow /etc/cron.d/cron.deny /etc/cron.allow /etc/cron.deny"
for list in $FILE_CRONUSER; do
	echo " " >> $CREATE_FILE 2>&1
	echo "☞ "$list" 파일" >> $CREATE_FILE 2>&1
	if [ -f $list ]; then
		cat $list							>> $CREATE_FILE 2>&1
	else
		echo $list" 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi
done
echo " " >> $CREATE_FILE 2>&1
echo "[참고] /var/spool/cron 디렉토리" >> $CREATE_FILE 2>&1
	if [ -d /var/spool/cron/crontabs/ ];then
		ls -alL /var/spool/cron/crontabs>> $CREATE_FILE 2>&1
	else
		ls -alL /var/spool/cron>> $CREATE_FILE 2>&1
	fi
	echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-133 END__##>"
echo "<##__SRV-133 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-142 START__##>"
echo "<##__SRV-142 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-142  root 계정과 동일한 UID 금지                                          " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - root 계정만 UID가 0일 경우                                   " >> $CREATE_FILE 2>&1  
echo "       취약 - root 계정 이외 UID가 0이 존재할 경우                " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ UID=0인 계정 목록" >> $CREATE_FILE 2>&1
awk -F: '$3==0' /etc/passwd >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-142 END__##>"
echo "<##__SRV-142 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-143 START__##>"
echo "<##__SRV-143 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-143 일반 계정과 동일한 UID 금지                                                     " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 동일한 UID가 존재하지 않을 경우                              " >> $CREATE_FILE 2>&1  
echo "      취약 - 동일한 UID가 존재할 경우                                     " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
for uid in `cat /etc/passwd | awk -F":" '{print $3}'`
do
	cat /etc/passwd | awk -F":" '$3=="'${uid}'" { print "UID=" $3 " → " $1 }'        > equaluid.txt
	if [ `cat equaluid.txt | wc -l` -gt 1 ]
	then
		cat equaluid.txt >> total-equaluid.txt
	fi
done
if [ -f total-equaluid.txt ]
	then
		if [ `sort -k 1 total-equaluid.txt | wc -l` -gt 1 ]
			then
				sort -k 1 total-equaluid.txt | uniq -d                     >> $CREATE_FILE 2>&1
			else
				echo "동일한 UID를 사용하는 계정이 발견되지 않았습니다."   >> $CREATE_FILE 2>&1
		fi
	else
		echo "동일한 UID를 사용하는 계정이 발견되지 않았습니다."           >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
rm -rf equaluid.txt
rm -rf total-equaluid.txt
echo "<##__SRV-143 END__##>"
echo "<##__SRV-143 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-144 START__##>"
echo "<##__SRV-144 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-144 /dev에 존재하지 않는 device 파일 점검                               " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - dev 에 존재하지 않은 device 파일을 점검하고, 존재하지 않은 device 을 제거 했을 경우  " >> $CREATE_FILE 2>&1  
echo "      취약 - dev 에 대한 파일점검을 하지 않거나, 존재하지 않은 device 파일을 방치 했을 경우 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "참고 major, minor number 존재하지 않는 파일을 검색                       " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ /dev 디렉토리 내 파일 목록" >> $CREATE_FILE 2>&1
find /dev \( -type f -o -type c -o -type b \) -ls 	>> dv.txt 
if [ `cat  dv.txt |wc -l` -ge 1 ]; then
   cat dv.txt >> $CREATE_FILE 2>&1
else
   echo "/dev 디렉토리에 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
rm -rf dv.txt
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-144 END__##>"
echo "<##__SRV-144 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-145 START__##>"
echo "<##__SRV-145 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-145 홈디렉토리로 지정한 디렉토리의 존재 관리                            " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 홈 디렉터리가 존재하지 않는 계정이 발견되지 않는 경우        " >> $CREATE_FILE 2>&1  
echo "      취약 - 홈 디렉터리가 존재하지 않는 계정이 발견된 경우          " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
for dir in $HOMEDIRS
do
	if [ ! -d $dir ]
		then
			cat /etc/passwd | awk -F":" '$6=="'${dir}'" { print "☞ "$1 "계정의 홈디렉토리(" $6 ")가 존재하지 않습니다" }' >> homelist.txt
	fi
done
if [ -f homelist.txt ] ;
	then 
		cat homelist.txt >> $CREATE_FILE 2>&1
	else 
		echo " 홈 디렉터리가 존재하지 않는 계정이 없습니다." >> $CREATE_FILE 2>&1
fi
rm -rf homelist.txt
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-145 END__##>"
echo "<##__SRV-145 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-146 START__##>"
echo "<##__SRV-146 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-146 ftp 계정 shell 제한                                                 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - ftp 계정에 shell 권한이 부여된 경우                          " >> $CREATE_FILE 2>&1  
echo "       취약 - ftp 계정에 shell 권한이 부여되지 않은 경우                   " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ FTP 실행 확인"  >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "ftp" | grep -v grep | wc -l` -ge 1 ]; then
	ps -ef | grep "ftp" | grep -v grep >> $CREATE_FILE 2>&1
else
	echo "ftp가 비실행 중입니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "☞ FTP 계정 확인"  >> $CREATE_FILE 2>&1
if [ `cat /etc/passwd | grep ftp | wc -l` -gt 0 ]
then
	cat /etc/passwd | grep ftp                                                    >> $CREATE_FILE 2>&1
else
	echo "ftp 계정이 존재하지 않습니다."                                          >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-146 END__##>"
echo "<##__SRV-146 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-147 START__##>"
echo "<##__SRV-147 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-147 SNMP 서비스 구동 점검                                               " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - SNMP 서비스를 사용하지 않을 경우                                  " >> $CREATE_FILE 2>&1  
echo "       취약 - SNMP 사용하지 않거나 불필요 시 운영되는 경우                      " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep snmp | grep -v grep | wc -l` -eq 0 ];
  then
    echo "SNMP가 비실행중입니다. "  >> $CREATE_FILE 2>&1
  else 
   ps -ef | grep snmp | grep -v grep >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-147 END__##>"
echo "<##__SRV-147 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-148 START__##>"
echo "<##__SRV-148 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-148 Apache 웹서비스 정보 숨김                                           " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - ServerTokens Prod, ServerSignature Off로 설정되어있는 경우      " >> $CREATE_FILE 2>&1  
echo "      취약 - ServerTokens Prod, ServerSignature Off로 설정되어있지 않은 경우 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "참고 -Prod = 웹 서버 종류          Server: Apache                          " >> $CREATE_FILE 2>&1  
echo "    -Min = Prod + 웹 서버 버전    Server: Apache 13.0                     " >> $CREATE_FILE 2>&1  
echo "    -OS = Min + 운영체제         Server: Apache 13.0 (Unix)              " >> $CREATE_FILE 2>&1  
echo "    -Full = OS + 설치 정보       Server: Apache (Unix) PHP3.0 MyMod 1.2  " >> $CREATE_FILE 2>&1  
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "grep" | wc -l` -ge 1 ] ; then
	if [ -f "$webconf_file" ]; then
		if [ `cat "$webconf_file" | egrep -i 'servertokens|serversignature' | grep -v '#' | wc -l` -ge 1 ]; then
			cat "$webconf_file" | egrep -i 'servertokens|serversignature' | grep -v '#'			>> $CREATE_FILE 2>&1
		else
			echo "servertokens, serversignature 설정이 없습니다." >> $CREATE_FILE 2>&1
		fi
	else
		echo $webconf_file"이 존재하지 않습니다">> $CREATE_FILE 2>&1
	fi
else
	echo "Apache Disable"									>> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-148 END__##>"
echo "<##__SRV-148 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-158 START__##>"
echo "<##__SRV-158 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-158 불필요한 TELNET 서비스 구동 여부                                 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - ssh를 사용하는 경우                                          " >> $CREATE_FILE 2>&1  
echo "      취약 - ssh를 사용하지 않거나 telnet을 사용하는 경우             " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ps -ef | egrep "ssh|telnet" | grep -v grep >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-158 END__##>"
echo "<##__SRV-158 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-159 START__##>"
echo "<##__SRV-159 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-159 원격 접속 세션 타임아웃 미설정                   		                             " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 접속한 사용자가 일정기간 사용하지 않을 경우 자동으로 세션이 종료되도록 "					   >> $CREATE_FILE 2>&1 
echo "            설정되어 있는 경우 " 															   >> $CREATE_FILE 2>&1 
echo "      취약 - 접속한 사용자가 일정기간 사용하지 않을 경우 자동으로 세션이 종료되도록 " 					   >> $CREATE_FILE 2>&1 
echo "            설정되어 있지 않은 경우 " 														   >> $CREATE_FILE 2>&1 
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "[1] sh, ksh, bash 쉘을 사용하는 경우" >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]; then
	cat /etc/profile | grep -i 'TIMEOUT'   >> $CREATE_FILE 2>&1
else
	echo "/etc/default/login파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "[2] csh 쉘을 사용하는 경우 (/etc/csh.login 파일의 autologout 설정)" >> $CREATE_FILE 2>&1
if [ -f /etc/csh.login ]
 then
    cat /etc/csh.login | grep -i autologout >> $CREATE_FILE 2>&1
 else
  echo "/etc/csh.login 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "☞ SSH 설정 확인 " >> $CREATE_FILE 2>&1
FILE_SSHD_CONF="/etc/ssh/sshd_config /opt/ssh/etc/sshd_config /etc/sshd_config /usr/local/etc/sshd_config /usr/local/sshd/etc/sshd_config /usr/local/ssh/etc/sshd_config /etc/ssh/ssh_config"
for SSHD_CONF in $FILE_SSHD_CONF; 
	do
		if [ -f $SSHD_CONF ]; then
			echo "* "$SSHD_CONF" 파일"  >> $CREATE_FILE 2>&1
			if [ `cat $SSHD_CONF | egrep -i 'ClientAliveInterval|ClientAliveCountMax' | wc -l` -eq 0 ]; then
				echo "ClientAliveInterval, ClientAliveCountMax 설정이 되어있지 않습니다." >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
			else
				cat $SSHD_CONF | egrep -i "ClientAliveInterval|ClientAliveCountMax"  >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
			fi
		fi
	done
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-159 END__##>"
echo "<##__SRV-159 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-161 START__##>"
echo "<##__SRV-161 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-161 Ftpusers 파일 소유자 및 권한 설정                                   " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - Ftpusers 파일 권한 640 이하(FTP 서비스 비활성화)             " >> $CREATE_FILE 2>&1  
echo "      취약 - Ftpusers 파일 권한 640 초과면취약                            " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ServiceDIR="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list"
for file in $ServiceDIR
do
	if [ -f $file ]
	then
		ls -alL $file                                                                      >> ftpusers.txt
	fi
done

if [ `cat ftpusers.txt | wc -l` -ge 1 ]
then
	cat ftpusers.txt | grep -v "^ *$"                                                            >> $CREATE_FILE 2>&1
else
	echo " ftpusers 파일을 찾을 수 없습니다. (FTP 서비스 동작 시 취약)"                        >> $CREATE_FILE 2>&1
fi
rm -f ftpusers.txt
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-161 END__##>"
echo "<##__SRV-161 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "<##__SRV-162 START__##>"
echo "<##__SRV-162 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-162 이벤트 로그에 대한 접근 권한 설정 미비                                   " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - su 명령의 사용에 대한 로깅이 적절하게 되고 있는 경우             " >> $CREATE_FILE 2>&1  
echo "      취약 - su 명령의 사용에 대한 로깅이 이루어지지 않는 경우        " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "[참고]  auth	sufficient	pam_rootko.so        							     " >> $CREATE_FILE 2>&1  
echo "       ㄴroot 사용자가 su명령 사용 시 패스워드를 묻지 않는 설정    " >> $CREATE_FILE 2>&1  
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
#금보원 스크립트에서 이 설정 확인함
echo "☞ pam.d 파일 rootok 설정 확인 "  >> $CREATE_FILE 2>&1
if [ `grep rootok /etc/pam.d/su | wc -l` -eq 0 ]; then
	echo "rootok 설정이 없음" >> $CREATE_FILE 2>&1
else
	grep rootok /etc/pam.d/su  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "☞ sulog 확인(15개 line만 출력)"  >> $CREATE_FILE 2>&1
if [ -f /var/log/sulog ]; then
	ls -al /var/log/sulog  >> $CREATE_FILE 2>&1
	cat /var/log/sulog | head -n 15 >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
else
	echo '/var/log/sulog 파일이 존재하지 않습니다.' >> $CREATE_FILE 2>&1  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	logconf="/etc/syslog.conf /etc/rsyslog.conf"
	for lists in $logconf; do
	if [ -f $lists ]; then
		echo "☞ "$lists"파일 authpriv 설정"  >> $CREATE_FILE 2>&1
		cat $lists | grep -v '^#' | grep authpriv  >> sl.txt
		cat sl.txt >> $CREATE_FILE 2>&1
		awk '{print $2}' sl.txt >> sl2.txt
		while read line
		do
			echo " " >> $CREATE_FILE 2>&1
			echo "☞ "$line" 로그 확인(15개 line만 출력)" >> $CREATE_FILE 2>&1
			cat $line | head -n 15 >> $CREATE_FILE 2>&1
		done < sl2.txt
		rm -rf sl.txt
		rm -rf sl2.txt
	fi
	done
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-162 END__##>"
echo "<##__SRV-162 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-163 START__##>"
echo "<##__SRV-163 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-163 시스템 사용 주의사항 미출력                                          " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 로그인 시 시스템 사용 주의사항 등의 안내(경고) 문구를 표시하고 있는 경우  " >> $CREATE_FILE 2>&1  
echo "      취약 - 로그인 시 시스템 사용 주의사항 등의 안내(경고) 문구를 표시하지 않는 경우 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
# 금보원 스크립트에서 확인하는 파일만 확인
echo "☞ /etc/motd 파일 설정(로그인 후 출력)"                                                  >> $CREATE_FILE 2>&1
if [ -f /etc/motd ]
	then
		cat /etc/motd                                               >> $CREATE_FILE 2>&1
	else
		echo "/etc/motd 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "☞ /etc/issue(로그인 전 출력) 파일 설정"                                        >> $CREATE_FILE 2>&1
if [ -f /etc/issue ]
	then
		cat /etc/issue                                               >> $CREATE_FILE 2>&1
	else
		echo "/etc/issue 파일이 존재하지 않습니다."                  >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "☞ /etc/default/telnetd 파일 설정(TELNET배너)"                                        >> $CREATE_FILE 2>&1
if [ -f /etc/default/telnetd ]
	then
		cat /etc/default/telnetd | grep -i "BANNER="                                              >> $CREATE_FILE 2>&1
	else
		echo "/etc/default/telnetd 파일이 존재하지 않습니다."                  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-163 END__##>"
echo "<##__SRV-163 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-164 START__##>"
echo "<##__SRV-164 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-164 계정이 존재하지 않는 GID 금지                                       " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 계정이 없는 GID가 존재하지 않을 경우                         " >> $CREATE_FILE 2>&1  
echo "      취약 - 계정이 없는 GID가 존재할 경우                                " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ 계정이 없는 GID 확인" >> $CREATE_FILE 2>&1
awk -F: '{print $4}' /etc/passwd | sort | uniq -u > passwd_GID.txt 
awk -F: '{print $3}' /etc/group | sort | uniq -u > group_GID.txt 
# passwd 파일의 GID와 group 파일 GID 비교 후, 중복되지 않은 GID만 출력
comm -23 group_GID.txt passwd_GID.txt > notgid.txt

# group파일에서 중복되지 않은 GID를 가지란 라인 출력
if [ `cat notgid.txt | wc -l` -eq 0 ] ; 
	then
		echo "계정이 없는 GID가 존재하지 않습니다." >> $CREATE_FILE 2>&1
	else
		while read line
		do
			cat /etc/group | grep ":"$line":" >> notgid2.txt
		done < notgid.txt
fi	
# 보조그룹으로 포함된 계정 존재 시 출력X
awk -F: '$4 == ""' notgid2.txt >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1
rm -rf passwd_GID.txt
rm -rf group_GID.txt
rm -rf notgid.txt
rm -rf notgid2.txt
echo "<##__SRV-164 END__##>"
echo "<##__SRV-164 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-165 START__##>"
echo "<##__SRV-165 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-165 사용자 shell 점검                                                   " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 로그인이 불필요한 계정에 대한 shell 부여가 적절한 경우       " >> $CREATE_FILE 2>&1  
echo "      취약 - 로그인이 불필요한 계정에 대한 shell 부여가 적절하지 않은 경우 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
  echo "☞ nologin, false 쉘이 부여되지 않은 계정" >> $CREATE_FILE 2>&1
    cat /etc/passwd | grep -v "nologin" | grep -v "false" >> $CREATE_FILE 2>&1
  else
    echo "/etc/passwd 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/passwd ]
  then
  echo "☞ nologin, false 쉘이 부여된 계정" >> $CREATE_FILE 2>&1
    cat /etc/passwd | egrep -i "nologin|false" >> $CREATE_FILE 2>&1
  else
    echo "/etc/passwd 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "☞ 마지막으로 로그인한 날짜" >> $CREATE_FILE 2>&1
lastlog  >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "[참고] daemon| bin| sys| adm| listen| nobody| nobody4| noaccess| diag| listen| operator| games| gopher 계정 shell 점검" >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
	then
		cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" >> $CREATE_FILE 2>&1
	else
		echo "/etc/passwd 파일이 없습니다."     >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-165 END__##>"
echo "<##__SRV-165 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-166 START__##>"
echo "<##__SRV-166 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-166 숨겨진 파일 및 디렉토리 검색 및 제거                                " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 숨겨진 파일 및 디렉토리 중 불필요한 파일 존재하지 않을 경우  " >> $CREATE_FILE 2>&1  
echo "      취약 - 숨겨진 파일 및 디렉토리 중 불필요한 파일 존재할 경우         " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
#dirr2="/export /bin /sbin /var /tmp /temp"
find / -type d -name ".*" -ls >> dirhidden.txt
find / -type f -name ".*" -ls >> filehidden.txt
echo "☞ 숨겨진 파일 목록" >> $CREATE_FILE 2>&1
if [ `cat filehidden.txt | wc -l` -ge 1 ]; then
	find / -type f -name ".*" -ls >> $CREATE_FILE 2>&1
else
	echo "숨겨진 파일이 존재하지 않습니다" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "☞ 숨겨진 디렉터리 목록" >> $CREATE_FILE 2>&1
if [ `cat dirhidden.txt | wc -l` -ge 1 ]; then
	find / -type d -name ".*" -ls >> $CREATE_FILE 2>&1
else
	echo "숨겨진 파일이 존재하지 않습니다" >> $CREATE_FILE 2>&1
fi
rm -rf dirhidden.txt
rm -rf filehidden.txt
echo " " >> $CREATE_FILE 2>&1
echo "<##__SRV-166 END__##>"
echo "<##__SRV-166 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "<##__SRV-168 START__##>"
echo "<##__SRV-168 START__##>" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-168  정책에 따른 시스템 로깅 설정                                       				 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 이벤트 감사 정책이 설정된 경우                          						     " >> $CREATE_FILE 2>&1  
echo "       취약 - 이벤트 감사 정책이 설정되지 않은 경우                    						 " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "참고 auth : 로그인 등의 인증 프로그램 유형이 발생한 메시지          							     " >> $CREATE_FILE 2>&1  
echo "    authpriv : 개인인증을 요구하는 프로그램 유형이 발생한 메시지     							 " >> $CREATE_FILE 2>&1  
echo "    cron : cron이나 at과 같은 프로그램이 발생하는 메시지                						 " >> $CREATE_FILE 2>&1  
echo "    daemon : telnetd, ftpd등과 같은 데몬이 발생한 메시지                				 	     " >> $CREATE_FILE 2>&1  
echo "    kern : 커널이 발생한 메시지                                   					         " >> $CREATE_FILE 2>&1  
echo "    lpr : 프린터 유형의 프로그램이 발생한 메시지                    						     " >> $CREATE_FILE 2>&1  
echo "    lpr : 프린터 유형의 프로그램이 발생한 메시지           					                 " >> $CREATE_FILE 2>&1  
echo "    mail : 메일시스템에서 발생한 메시지                   						             " >> $CREATE_FILE 2>&1  
echo "    news : 유즈넷 뉴스 프로그램 유형이 발생한 메시지      						                 " >> $CREATE_FILE 2>&1  
echo "    syslog : syslog 프로그램 유형이 발생한 메시지        							         " >> $CREATE_FILE 2>&1  
echo "    user : 사용자 프로세스                             					                 " >> $CREATE_FILE 2>&1  
echo "    uucp : 시스템이 발생한 메시지                      					                 " >> $CREATE_FILE 2>&1  
echo "    local0 : 여분으로 남겨둔 유형                         					                 " >> $CREATE_FILE 2>&1  
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" 																				   >> $CREATE_FILE 2>&1
echo " " 																			  		   >> $CREATE_FILE 2>&1
echo " [1] SYSLOG 데몬 동작 확인"                                                                 >> $CREATE_FILE 2>&1
ps -ef | grep -i 'syslog' | grep -v 'grep'                               					   >> $CREATE_FILE 2>&1
echo " "                                                                   					   >> $CREATE_FILE 2>&1
ps -ef | egrep -i 'syslog|log'                                                				   >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " [2] SYSLOG 설정 확인"                                                                     >> $CREATE_FILE 2>&1
sysfile='/etc/syslog.conf /etc/rsyslog.conf'
for list in $sysfile
do
if [ -f $list ];
then
	echo "----------------------------------------"                                    		  >> $CREATE_FILE 2>&1
	echo $list" 파일 설정"                                       								  >> $CREATE_FILE 2>&1
	echo "----------------------------------------"                                        	  >> $CREATE_FILE 2>&1
	cat $list | grep -v "^#" | grep -v "^ *$"                                         		  >> $CREATE_FILE 2>&1
	echo " "																				  >> $CREATE_FILE 2>&1
else
	echo "☞ "$list" 파일이 존재하지 않습니다."                                             		  >> $CREATE_FILE 2>&1
fi
done
echo " " 																					  >> $CREATE_FILE 2>&1
echo "<##__SRV-168 END__##>"
echo "<##__SRV-168 END__##>" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "<##__[참고] tomcat-user.xml 점검__##>"
echo "<##__[참고] tomcat-user.xml 점검__##>"													>> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "SRV-060 미흡한 Apache Tomcat 기본 계정 사용 여부                                      " >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 양호 - 기본적으로 설정되는 tomcat 계정/패스워드를 사용하지 않는 경우                " >> $CREATE_FILE 2>&1  
echo "       취약 - 기본적으로 설정되는 tomcat 계정/패스워드를 사용하는 경우         			" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "----------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo " CATALINA_HOME과 CATALINA_BASE에 설정된 경로가 다를 경우를 대비하여 두가지 모두 확인합니다.	" >> $CREATE_FILE 2>&1
echo " 따라서, tomcat-users.xml 파일이 중복되어 출력될 수 있습니다. 참고 부탁 드립니다.			" >> $CREATE_FILE 2>&1
echo "----------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ps auxwww | egrep 'catalina\.startup\.Bootstrap' | egrep -v "grep|java -server" | awk '{for (i=1;i<=NF;i++) {if ($i ~/(Dcatalina\.home)/) {print $i}}}' | awk -F"=" '{ print $2 }' | grep '^/' | sort -u >> tomcatusersxml.txt
ps auxwww | egrep 'catalina\.startup\.Bootstrap' | egrep -v "grep|java -server" | awk '{for (i=1;i<=NF;i++) {if ($i ~/(Dcatalina\.base)/) {print $i}}}' | awk -F"=" '{ print $2 }' | grep '^/' | sort -u >> tomcatusersxml.txt
if [ `cat tomcatusersxml.txt | wc -l` -ge 1 ] ; then
		while read line
		do
			echo " "																						>> $CREATE_FILE 2>&1
			echo "==============================================================================="			>> $CREATE_FILE 2>&1
			echo "☞ 파일 경로 :" $line																			>> $CREATE_FILE 2>&1
			echo "-------------------------------------------------------------------------------"			>> $CREATE_FILE 2>&1
			echo "tomcat-users.xml 파일]"																		>> $CREATE_FILE 2>&1
			cat $line/conf/tomcat-users.xml																	>> $CREATE_FILE 2>&1
			echo "==============================================================================="			>> $CREATE_FILE 2>&1
				done < tomcatusersxml.txt
	else
		echo "tomcat Disable"																				>> $CREATE_FILE 2>&1
	fi																										
rm -rf tomcatusersxml.txt
echo " " >> $CREATE_FILE 2>&1
echo "<##__[참고] tomcat-user.xml 점검 END__##>"
echo "<##__[참고] tomcat-user.xml 점검 END__##>"		>> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "[[==END_RESULT==]]"
echo "[[==END_RESULT==]]" >> $CREATE_FILE 2>&1
echo "******************************** END ********************************" 