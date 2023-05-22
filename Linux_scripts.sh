#!/bin/sh 

lang_check=`locale -a 2>/dev/null | grep "en_US" | egrep -i "(utf8|utf-8)"`
if [ "$lang_check" = "" ]; then
    lang_check="C"
fi

LANG="$lang_check"
LC_ALL="$lang_check"
LANGUAGE="$lang_check"
export LANG
export LC_ALL
export LANGUAGE

if [ "`command -v netstat 2>/dev/null`" != "" ] || [ "`which netstat 2>/dev/null`" != ""]; then #command -v zuldaepath of command
    port_cmd="netstat"
else
    port_cmd="ss"
fi

if [ "`command -v systemctl 2>/dev/null`" != "" ] || [ "`which systemctl 2>/dev/null`" != "" ]; then
        systemctl_cmd="systemctl"
fi

RESULT_FILE="result_collect_`date +\"%Y%m%d%H%M\"`.txt"

echo "[Start Script]"
echo "================ Linux Security Check Script Start ================" > $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################
# -  u-01
##############################################

echo "[ U-01 ] : Check"
echo "================ [U-01 START] ================" > $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

echo "1. SSH" >> $RESULT_FILE 2>&1
echo "1-1. SSH Process Check" >> $RESULT_FILE 2>&1
get_ssh_ps=`ps -ef | grep -v "grep" | grep "sshd"`
if [ "$get_ssh_ps" != "" ]; then
    echo "$get_ssh_ps" >> $RESULT_FILE 2>&1
else
    echo "Not Found Process" >> $RESULT_FILE 2>&1
fi
echo "" >> $RESULT_FILE 2>&1


echo "1-2. SSH Service Check" >> $RESULT_FILE 2>&1
if [ "$systemctl_cmd" != "" ]; then
    get_ssh_service=`$systemctl_cmd list-units --type service | egrep '(ssh|sshd)\.service' | sed -e 's/^ *//g' -e 's/^ *//g' | tr -s " \t" `
    if [ "$get_ssh_service" != "" ]; then
        echo "$get_ssh_service" >> $RESULT_FILE 2>&1
    else
        echo "Not Found Service" >> $RESULT_FILE 2>&1
    fi
else
    echo "Not Found Systemctl Command" >> $RESULT_FILE 2>&1
fi
echo "" >> $RESULT_FILE 2>&1

echo "1-3. SSH Port Check" >> $RESULT_FILE 2>&1
if [ "$port_cmd" != "" ]; then
    get_ssh_port=`$port_cmd -na | grep "tcp" | grep "LISTEN" | grep ':22[ \t]'`
    if [ "$get_ssh_port" != "" ]; then
        echo "$get_ssh_port" >> $RESULT_FILE 2>&1
    else
        echo "Not Found Port" >> $RESULT_FILE 2>&1
    fi
else
    echo "Not Found Port Command" >> $RESULT_FILE 2>&1
fi


if [ "$get_ssh_ps" != "" ] || [ "$get_ssh_service" != "" ] || [ "$get_ssh_port" != "" ]; then
    echo "" >> $RESULT_FILE 2>&1
    echo "1-4. SSH Configuration File Check" >> $RESULT_FILE 2>&1
    if [ -f "/etc/ssh/sshd_config" ]; then
        get_ssh_config=`cat /etc/ssh/sshd_config |egrep -v '^#|^$' | grep "PermitRootLogin"`
        if [ "$get_ssh_config" != "" ]; then
            echo "/etc/ssh/sshd_config : $get_ssh_config" >> $RESULT_FILE 2>&1
            get_conf_check=`echo "$get_ssh_conf" | awk '{print $2}'`
            if [ "$get_conf_check" = "no" ]; then
                ssh_flag=1
            else
                ssh_flag=0
            fi
        else
            ssh_flag=1
            echo "/etc/ssh/sshd_config : Not Found PermitRootLogin Configuration" >> $RESULT_FILE 2>&1
        fi
    else
        ssh_flag=2
        echo "Not Found SSH Configuration File" >> $RESULT_FILE 2>&1
    fi
    echo "" >> $RESULT_FILE 2>&1
else
    ssh_flag=1
fi


echo "2. Telnet" >> $RESULT_FILE 2>&1
echo "2-1. Telnet Process Check" >> $RESULT_FILE 2>&1
get_telnet_ps=`ps -ef | grep -v "grep" | grep "telnet"`
if [ "$get_telnet_ps" != "" ]; then
    echo "$get_telnet_ps" >> $RESULT_FILE 2>&1
else
    echo "Not Found Process" >> $RESULT_FILE 2>&1
fi
echo "" >> $RESULT_FILE 2>&1

echo "2-2. Telnet Service Check" >> $RESULT_FILE 2>&1
if [ "$systemctl_cmd" != "" ]; then
    get_telnet_service=`$systemctl_cmd list-units --type service | egrep '(telnet|telnetd)\.service' | sed -e 's/^ *//g' -e 's/^    *//g' | tr -s " \t"`
    if [ "$get_telnet_service" != "" ]; then
        echo "$get_telnet_service" >> $RESULT_FILE 2>&1
    else
        echo "Not Found Service" >> $RESULT_FILE 2>&1
    fi
else
    echo "Not Found systemctl Command" >> $RESULT_FILE 2>&1
fi
echo "" >> $RESULT_FILE 2>&1


echo "2-3. Telnet Port Check" >> $RESULT_FILE 2>&1
if [ "$port_cmd" != "" ]; then
    get_telnet_port=`$port_cmd -na | grep "tcp" | grep "LISTEN" |grep ':23[ \t]'`
    if [ "$get_telnet_port" != "" ]; then
        echo "$get_telnet_port" >> $RESULT_FILE 2>&1
    else
        echo "Not Found Port" >> $RESULT_FILE 2>&1
    fi
else
    echo "Not Found Port Command" >> $RESULT_FILE 2>&1
fi

if [ "$get_telnet_ps" != "" ] || [ "$get_telnet_service" != "" ] || [ "$get_telnet_port" != "" ]; then
    telnet_flag=0
    echo "" >> $RESULT_FILE 2>&1
    echo "2.4 Telnet Configuration Check" >> $RESULT_FILE 2>&1
    if [ -f "/etc/pam.d/remote" ]; then
        pam_file="/etc/pam.d/remote"
    elif [ -f "/etc/pam.d/login" ]; then
        pam_file="/etc/pam.d/login"
    fi

    if [ "$pam_file" != "" ]; then
        echo "- $pam_file" >> $RESULT_FILE 2>&1
        get_conf=`cat $pam_file | egrep -v '^#|^$' | grep "pam_securetty.so"`
        if [ "$get_conf" != "" ]; then
            echo "$get_conf" >> $RESULT_FILE 2>&1
            if [ -f "/etc/securetty" ]; then
                echo "- /etc/securetty" >> $RESULT_FILE 2>&1
                echo "`cat /etc/securetty`" >> $RESULT_FILE 2>&1
                get_pts=`cat /etc/securetty | egrep -v '^#|^$' | grep "^[ \t]*pts"`
                if [ "$get_pts" = "" ]; then
                    telnet_flag=1
                fi
            else
                echo "Not Found Telnet tty Configuration File" >> $RESULT_FILE 2>&1
            fi
        else
            echo "$pam_file : Not Found pam_securetty.so Configuration" >> $RESULT_FILE 2>&1
        fi
    else
        telnet_flag=2
        echo "Not Found Telnet Pam Configuration File" >> $RESULT_FILE 2>&1
    fi
else
    telnet_flag=1
fi


# chwiyak : 0, yangho : 1, gumto : 2
if [ $ssh_flag -eq 1 ] && [ $telnet_flag -eq 1 ]; then
    echo "result: yangho" >> $RESULT_FILE 2>&1
elif [ $ssh_flag -eq 0 ] || [ $telnet_flag -eq 0 ]; then
    echo "result: chwiyak" >> $RESULT_FILE 2>&1
elif [ $ssh_flag -eq 2 ] || [ $telnet_flag -eq 2 ]; then
    echo "result: gumto" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "================= [U-01 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1



#################################################################
# U-02 
################################################################


# Check if password complexity is enforced
echo "[ U-02 ] : Check"
echo "================ [U-02 START] ================" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
check=0
function w02check1 ()
{
        local check1=0
        pc_chk1=`grep "password[ \t]*requisite[ \t]*pam_cracklib.so" /etc/pam.d/system-auth | awk -F" " '{print $4 $5 $6 $7 $8}'` >> $RESULT_FILE 2>&1
        echo "$pc_chk1" >> $RESULT_FILE 2>&1
        pc_chk1_1=`echo "$pc_chk1" | awk -F" " '{print $1}'| awk -F"=" '{print $2}'`
        pc_chk1_2=`echo "$pc_chk1" | awk -F" " '{print $2}'| awk -F"=" '{print $2}'`
        pc_chk1_3=`echo "$pc_chk1" | awk -F" " '{print $3}'| awk -F"=" '{print $2}'`
        pc_chk1_4=`echo "$pc_chk1" | awk -F" " '{print $4}'| awk -F"=" '{print $2}'`
        pc_chk1_5=`echo "$pc_chk1" | awk -F" " '{print $5}'| awk -F"=" '{print $2}'`
        if [ "$pc_chk1_2" -eq -1 ] ; then
                check1=`expr $check1 + 1`
        fi
        if [ "$pc_chk1_3" -eq -1 ] ; then
                check1=`expr $check1 + 1`
        fi
        if [ "$pc_chk1_4" -eq -1 ] ; then
                check1=`expr $check1 + 1`
        fi
        if [ "$pc_chk1_5" -eq -1 ] ; then
                check1=`expr $check1 + 1`
        fi
        if [ "$pc_chk1_1" -ge 8 ] && [ "$check1" -ge 3 ]; then
                check=`expr $check + 1`
        fi

}

function w02check2 ()
{
        local check2=0
        first=`cat /etc/security/pwquality.conf | sed -e 's/^ *//g' -e 's/^  *//g' | egrep -v '^$|^//|^#'`
        echo "$first" >> $RESULT_FILE 2>&1
        if [ "$first" != "" ]; then
                pc_chk2_1=`echo "$first" | grep 'minlen' | awk -F" " '{print $3}'`
                pc_chk2_2=`echo "$first" | grep 'dcredit' | awk -F" " '{print $3}'`
                pc_chk2_3=`echo "$first" | grep 'ucredit' | awk -F" " '{print $3}'`
                pc_chk2_4=`echo "$first" | grep 'lcredit' | awk -F" " '{print $3}'`
                pc_chk2_5=`echo "$first" | grep 'ocredit' | awk -F" " '{print $3}'`

                if [ "$pc_chk2_2" -eq 1 ] ; then
                check1=`expr $check1 + 1`
                fi
                if [ "$pc_chk2_3" -eq 1 ] ; then
                        check1=`expr $check1 + 1`
                fi
                if [ "$pc_chk2_4" -eq 1 ] ; then
                        check1=`expr $check1 + 1`
                fi
                if [ "$pc_chk2_5" -eq 1 ] ; then
                        check2=`expr $check2 + 1`
                fi
                if [ "$pc_chk2_1" -ge 8 ] && [ "$check1" -ge 3 ]; then
                        check=`expr $check + 1`
                fi
        fi
}

function w02check3 ()
{
        local check3=0
        pc_chk3=`grep "password[ \t]*requisite[ \t]*pam_passwdqc.so" /etc/pam.d/system-auth | awk -F" " '{print $4}'| awk -F"=" '{print $2}'`
        echo "$pc_chk3" >> $RESULT_FILE 2>&1
        pc_chk3_1=`echo "$pc_chk1" | awk -F"," '{print $1}'`
        pc_chk3_2=`echo "$pc_chk1" | awk -F" " '{print $2}'`
        pc_chk3_3=`echo "$pc_chk1" | awk -F" " '{print $3}'`
        pc_chk3_4=`echo "$pc_chk1" | awk -F" " '{print $4}'`
        pc_chk3_5=`echo "$pc_chk1" | awk -F" " '{print $5}'`
        if [ "$pc_chk3_1" -eq "disabled" ] ; then
                check3=`expr $check3 + 1`
        fi
        if [ "$pc_chk3_2" -eq "disabled" ] ; then
                check3=`expr $check3 + 1`
        fi
        if [ "$pc_chk3_3" -eq "disabled" ] ; then
                check3=`expr $check3 + 1`
        fi
        if [ "$pc_chk3_4" -ge 8 ] ; then
                check3=`expr $check3 + 1`
        fi
        if [ "$pc_chk3_5" -ge 8 ] ; then
                check3=`expr $check3 + 1`
        fi
        if [ "$check3" -eq 5 ]; then
                check=`expr $check + 1`
        fi

}

pccheck1=`grep "password[ \t]*requisite[ \t]*pam_cracklib.so" /etc/pam.d/system-auth`
pccheck2=`grep "password[ \t]*requisite[ \t]*pam_pwquality.so" /etc/pam.d/system-auth`
pccheck3=`grep "password[ \t]*requisite[ \t]*pam_passwdqc.so" /etc/pam.d/system-auth`
if [ "$pccheck1" != "" ] ; then
        echo "$pccheck1" >> $RESULT_FILE 2>&1
        w02check1
elif [ "$pccheck2" != "" ] ; then
        echo "$pccheck2" >> $RESULT_FILE 2>&1
        w02check2
elif [ "$pccheck3" != "" ] ; then
        echo "$pccheck3" >> $RESULT_FILE 2>&1
        w02check3
fi

if [ $check -eq 1 ]; then
    echo "result: yangho" >> $RESULT_FILE 2>&1
else
    echo "result: chwiyak" >> $RESULT_FILE 2>&1
fi


echo "" >> $RESULT_FILE 2>&1
echo "================= [U-02  END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#################################################################
# - U-03
################################################################

echo "[U-03] : Check"
echo "=========[U-3 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

check=0
function w03check1 ()
{
        local check1=0
        al_chk1=`grep "auth[ \t]*required[ \t]*pam_tally.*.so" /etc/pam.d/system-auth" /etc/pam.d/system-auth | awk -F" " '{print $4}' | awk -F"=" '{print $2}'`
        echo "$al_chk3" >> $RESULT_FILE 2>&1
        al_chk2=`grep "account[ \t]*required[ \t]*pam_tally.*.so" /etc/pam.d/system-auth" /etc/pam.d/system-auth | awk -F" " '{print $4}' | awk -F"=" '{print $2}'`
        echo "$al_chk3" >> $RESULT_FILE 2>&1

        if [ "$al_chk1" -le 10 ] ; then
                check1=`expr $check1 + 1`
        fi
        if [ "$al_chk2" -le 10 ] ; then
                check1=`expr $check1 + 1`
        fi
        if [ "$check1" -eq 2 ]; then
                check=`expr $check + 1`
        fi

}

alcheck1=`grep "auth[ \t]*required[ \t]*pam_tally.*.so" /etc/pam.d/system-auth`
alcheck2=`grep "account[ \t]*required[ \t]*pam_tally.*.so" /etc/pam.d/system-auth`
if [ "$alcheck1" != "" ] && [ "$alcheck2" != "" ]; then
        echo "$alcheck1" >> $RESULT_FILE 2>&1
        echo "$alcheck2" >> $RESULT_FILE 2>&1
        w03check1
else
        echo "lock limit file is not exist" >> $RESULT_FILE 2>&1
fi


if [ $check -eq 1 ]; then
    echo "result: yangho" >> $RESULT_FILE 2>&1
else
    echo "result: chwiyak" >> $RESULT_FILE 2>&1
fi


echo "" >> $RESULT_FILE 2>&1
echo "=========[U-3 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


#################################################################
# -account management | U-04 Passwd File Protection
################################################################

echo "[U-04] : Check"
echo "=========[U-4 Passwd File Protection START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

pass_flag=0
sha_flag=0
echo "Shadow File Check" >> $RESULT_FILE 2>&1
if [ -f "/etc/shadow" ]; then
    echo "shadow file exist at /etc/shadow" >> $RESULT_FILE 2>&1
    echo "----Accounts In Shadow File----" >> $RESULT_FILE 2>&1
    echo "`cat "/etc/shadow" | awk -F":" '{print $1,$2;}'`" >> $RESULT_FILE 2>&1
    echo "----Accounts In Shadow File----" >> $RESULT_FILE 2>&1
    sha_flag=1
else
    echo "Shadow File Not Found" >> $RESULT_FILE 2>&1
fi
pass_chk=`cat "/etc/passwd" | awk -F":" '{if($2!="x") print $1;}'`
if [ "$pass_chk" != '' ]; then
    echo "----Chwiyak account----" >> $RESULT_FILE 2>&1
    echo "$pass_chk" >> $RESULT_FILE 2>&1
    echo "----Chwiyak account----" >> $RESULT_FILE 2>&1
else
    pass_flag=1
    echo "Password Is Encrypted" >> $RESULT_FILE 2>&1
fi


if [ $pass_flag -eq 1 ] || [ $sha_flag -eq 1 ]; then
    echo "RESULT = YANGHO" >> $RESULT_FILE 2>&1
else
    echo "RESULT = CHWIYAK" >> $RESULT_FILE 2>&1
fi



echo "" >> $RESULT_FILE 2>&1
echo "=========[U-4 Passwd File Protection END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


#################################################################
# - U-05 
################################################################
echo "[U-05] : Check"
echo "=========[U-5 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

w05chk=`echo $PATH | egrep "\.:|::|:.:" `
if [ "$w05chk" != "" ] ; then
        echo "$w05chk" >> $RESULT_FILE 2>&1
        echo "result: yangho" >> $RESULT_FILE 2>&1
else
        echo "nothing"  >> $RESULT_FILE 2>&1
        echo "result: chwiyak" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=========[U-5 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-06
##############################################

echo "[U-06] : Check"
echo "=========[U-6 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#w06chk=`find / \( -nouser -o -nogroup \) -print 2>/dev/null ` >> $RESULT_FILE 2>&1
w06chk=0
if [ "$w06chk" = "" ] ; then
        echo "nothing" >> $RESULT_FILE 2>&1
        echo "result: yangho" >> $RESULT_FILE 2>&1
else
        echo "$w06chk" >> $RESULT_FILE 2>&1
        echo "result: chwiyak" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=========[U-6 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-07
##############################################

echo "[U-07] : Check"
echo "=========[U-6 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

if [ -f "/etc/passwd" ]; then
    ls -l /etc/passwd >> $RESULT_FILE 2>&1
    permission_val=`stat -c '%a' /etc/passwd`
    owner_val=`stat -c '%U' /etc/passwd`
    owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
    group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
    other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`
    if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -le 4 ] && [ "$other_perm_val" -le 4 ] && [ "$owner_val" = "root" ]; then
        echo " rEsUlT: yangho" >> $RESULT_FILE 2>&1
    else
        echo " rEsUlT: chiyak" >> $RESULT_FILE 2>&1
    fi

else
    echo "Not Found /etc/passwd File" >> $RESULT_FILE 2>&1
    echo " rEsUlT: gumto" >> $RESULT_FILE 2>&1
fi


echo "" >> $RESULT_FILE 2>&1
echo "=========[U-7 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-08
##############################################

echo "[U-08] : Check"
echo "=========[U-8 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

if [ -f "/etc/shadow" ]; then
    ls -l /etc/shadow >> $RESULT_FILE 2>&1
    permission_val=`stat -c '%a' /etc/shadow`
    echo "$permission_val" >> $RESULT_FILE 2>&1
    owner_val=`stat -c '%U' /etc/shadow`
    owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
    group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
    other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`
    if [ "$permission_val" = 0 ] ; then
        owner_perm_val=0
        group_perm_val=0
        other_perm_val=0
    fi
    if [ "$owner_perm_val" -le 4 ] && [ "$group_perm_val" -eq 0 ] && [ "$other_perm_val" -eq 0 ] && [ "$owner_val" = "root" ]; then
        echo " rEsUlT: yangho" >> $RESULT_FILE 2>&1
    else
        echo " rEsUlT: chiyak" >> $RESULT_FILE 2>&1
    fi

else
    echo "Not Found /etc/shadow File" >> $RESULT_FILE 2>&1
    echo " rEsUlT: gumto" >> $RESULT_FILE 2>&1
fi


echo "" >> $RESULT_FILE 2>&1
echo "=========[U-8 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-09
##############################################

echo "[U-09] : Check"
echo "=========[U-9 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

if [ -f "/etc/hosts" ]; then
    ls -l /etc/hosts >> $RESULT_FILE 2>&1
    permission_val=`stat -c '%a' /etc/hosts`
    echo "$permission_val" >> $RESULT_FILE 2>&1
    owner_val=`stat -c '%U' /etc/hosts`
    owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
    group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
    other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`
    if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -le 4 ] && [ "$other_perm_val" -le 4 ] && [ "$owner_val" = "root" ]; then
        echo " rEsUlT: yangho" >> $RESULT_FILE 2>&1
    else
        echo " rEsUlT: chiyak" >> $RESULT_FILE 2>&1
    fi

else
    echo "Not Found /etc/hosts File" >> $RESULT_FILE 2>&1
    echo " rEsUlT: gumto" >> $RESULT_FILE 2>&1
fi


echo "" >> $RESULT_FILE 2>&1
echo "=========[U-9 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################
# -  u-10
##############################################

echo "[U-10] : Check"
echo "=========[U-10 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

if [ -f "/etc/inetd.conf" ]; then
    ls -l /etc/inetd.conf >> $RESULT_FILE 2>&1
    permission_val=`stat -c '%a' /etc/inetd.conf`
    echo "$permission_val" >> $RESULT_FILE 2>&1
    owner_val=`stat -c '%U' /etc/inetd.conf`
    owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
    group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
    other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`
    if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -eq 0 ] && [ "$other_perm_val" -eq 0 ] && [ "$owner_val" = "root" ]; then
        echo " rEsUlT: yangho" >> $RESULT_FILE 2>&1
    else
        echo " rEsUlT: chiyak" >> $RESULT_FILE 2>&1
    fi

else
    if [ -f "/etc/xinetd.conf" ]; then
        ls -l /etc/xinetd.conf >> $RESULT_FILE 2>&1
        permission_val=`stat -c '%a' /etc/xinetd.conf`
        echo "$permission_val" >> $RESULT_FILE 2>&1
        owner_val=`stat -c '%U' /etc/xinetd.conf`
        owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
        group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
        other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`
        if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -eq 0 ] && [ "$other_perm_val" -eq 0 ] && [ "$owner_val" = "root" ]; then
        echo " rEsUlT: yangho" >> $RESULT_FILE 2>&1
        else
          echo " rEsUlT: chiyak" >> $RESULT_FILE 2>&1
        fi
    else
        echo "Not Found /etc/inetd.conf File and /etc/xinetd.conf File" >> $RESULT_FILE 2>&1
        echo " rEsUlT: gumto" >> $RESULT_FILE 2>&1
    fi

fi


echo "" >> $RESULT_FILE 2>&1
echo "=========[U-10 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-11
##############################################

echo "[U-11] : Check"
echo "=========[U-11 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

if [ -f "/etc/syslog.conf" ]; then
    ls -l /etc/syslog.conf >> $RESULT_FILE 2>&1
    permission_val=`stat -c '%a' /etc/syslog.conf`
    echo "$permission_val" >> $RESULT_FILE 2>&1
    owner_val=`stat -c '%U' /etc/syslog.conf`
    owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
    group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
    other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`
    if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -le 4 ] && [ "$other_perm_val" -eq 0 ] && [ "$owner_val" = "root" ]; then
        echo " rEsUlT: yangho" >> $RESULT_FILE 2>&1
    else
        echo " rEsUlT: chiyak" >> $RESULT_FILE 2>&1
    fi

else
    if [ -f "/etc/rsyslog.conf" ]; then
        ls -l /etc/rsyslog.conf >> $RESULT_FILE 2>&1
        permission_val=`stat -c '%a' /etc/rsyslog.conf`
        echo "$permission_val" >> $RESULT_FILE 2>&1
        owner_val=`stat -c '%U' /etc/rsyslog.conf`
        owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
        group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
        other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`
        if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -le 4 ] && [ "$other_perm_val" -eq 0 ] && [ "$owner_val" = "root" ]; then
        echo " rEsUlT: yangho" >> $RESULT_FILE 2>&1
        else
          echo " rEsUlT: chiyak" >> $RESULT_FILE 2>&1
        fi
    else
        echo "Not Found /etc/syslog.conf File and /etc/rsyslog.cof File" >> $RESULT_FILE 2>&1
        echo " rEsUlT: gumto" >> $RESULT_FILE 2>&1
    fi

fi


echo "" >> $RESULT_FILE 2>&1
echo "=========[U-11 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-12
##############################################

echo "[U-12] : Check"
echo "=========[U-12 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

if [ -f "/etc/services" ]; then
    ls -l /etc/services >> $RESULT_FILE 2>&1
    permission_val=`stat -c '%a' /etc/services`
    echo "$permission_val" >> $RESULT_FILE 2>&1
    owner_val=`stat -c '%U' /etc/services`
    owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
    group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
    other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`
    if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -le 4 ] && [ "$other_perm_val" -le 4 ] && [ "$owner_val" = "root" ]; then
        echo " rEsUlT: yangho" >> $RESULT_FILE 2>&1
    else
        echo " rEsUlT: chiyak" >> $RESULT_FILE 2>&1
    fi

else
    echo "Not Found /etc/services File" >> $RESULT_FILE 2>&1
    echo " rEsUlT: gumto" >> $RESULT_FILE 2>&1
fi


echo "" >> $RESULT_FILE 2>&1
echo "=========[U-12 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-13
##############################################

echo "[U-13] : Check"
echo "=====================[U-13 SUID, SGID, Sticky bit seoljung letsgo]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
FILES="/sbin/dump /sbin/restore /sbin/unix_chkpwd /usr/bin/newgrp /usr/sbin/traceroute /usr/bin/at /usr/bin/lpq /usr/bin/lpq-lpd /usr/bin/lpr /usr/bin/lpr-lpd /usr/sbin/lpc /usr/sbin/lpc-lpd /usr/bin/lprm /usr/bin/lprm-lpd /test4.txt"

count=0

for file_chk in $FILES; do
    if [ -f "$file_chk" ]; then
        echo "`ls -al $file_chk`" >> $RESULT_FILE 2>&1

        if [ -h "$file_chk" ]; then
            count=`expr $count + 1`
            real_path=`readlink $file_chk`
            echo "Symbolic Link: `ls -al $real_path`" >> $RESULT_FILE 2>&1
            for path in $real_path; do
                if [ -h "$path" ]; then
                    real_path=`readlink $path`
                    echo "Symbolic Link: `ls -al $real_path`" >> $RESULT_FILE 2>&1
                fi
                file_chk="$path"
            done
        fi
        perm_chk=`ls -alL $file_chk | awk '{ print $1}' | grep -i 's' `
        if [ "$perm_chk" != "" ]; then
            count=`expr $count + 1`
        fi
    fi
done

echo "total chiyak file count : $count" >> $RESULT_FILE 2>&1

if [ $count -eq 0 ]; then
    echo " rEsUlT: yangho" >> $RESULT_FILE 2>&1
 else
    echo " rEsUlT: chiyak" >> $RESULT_FILE 2>&1
fi


echo "" >> $RESULT_FILE 2>&1
echo "================= [U-13 SUID, SGID, Sticky bit seoljung EnD]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-14
##############################################

echo "[U-14] : Check"
echo "=========[U-14 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


echo "" >> $RESULT_FILE 2>&1
echo "=========[U-14 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1



##############################################
# -  u-15
##############################################

echo "[U-15] : Check"
echo "=========[U-15 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#LOG_FILE="result_collect_`date +\"%Y%m%d%H%M\"`_log.txt"
#echo "`find / -type f -perm -2 -exec ls -l {} \; 2>/dev/null`" >>$LOG_FILE 2>&1
echo "please check result_collect_ `date +\"%Y%m%d%H%M\"`_log.txt file" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

echo "=========[U-15 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################
# -  u-16
##############################################
echo "[ U-16 ] : CHECK"
echo "==========[ U-16 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

get_dev=`find /dev -type f -exec ls -l {} \; `
# command result nothing -> PASS
if [ "$get_dev" = "" ]; then
	echo "dev file dosen't exist" >> $RESULT_FILE 2>&1
	echo "PASS" >> $RESULT_FILE 2>&1
else
# command result exist -> FAIL
	echo "dev file exist" >> $RESULT_FILE 2>&1
	echo "$get_dev" >> $RESULT_FILE 2>&1
	echo "FAIL" >> $RESULT_FILE 2>&1
fi

echo "[ U-16 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-16 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################
# -  u-17
##############################################
echo "[ U-17 ] : CHECK"
echo "==========[ U-17 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

get_cmd=`ls -al /etc/hosts.equiv 2>/dev/null `

hosts_file='/etc/hosts.equiv'
rhosts_file='~/.rhosts'


# command result nothing -> service not used -> pass
if [ "$get_cmd" = "" ]; then
        echo "service not used" >> $RESULT_FILE 2>&1
        echo "PASS" >> $RESULT_FILE 2>&1
else
# command result exist
        echo "login, shell, exec service used" >> $RESULT_FILE 2>&1

	able_service=$(systemctl list-unit-files | grep rsh.socket | awk '{print $2}')
		
	if [ "$able_service" = 'enabled' ]; then
		hosts_check=$(find $hosts_file -user root -perm 600 2>/dev/null)
		rhosts_check=$(find $rhosts_file -user root -perm 600 2>/dev/null)
		if [ -n "$hosts_check" ] && [ -n "$rhosts_check" ]; then
			config1=$(cat $hosts_file | grep "+")
			config2=$(cat $rhosts_file | grep "+")
			if [ -n "$config1" ] && [ -n "$config2" ]; then
				echo "login, shell, exec service not used || setting good" >> $RESULT_FILE 2>&1
				echo "PASS" >> $RESULT_FILE 2>&1
			else
				echo "login, shell, exec service used && setting bad" >> $RESULT_FILE 2>&1
				echo "FAIL" >> $RESULT_FILE 2>&1
			fi
		else
			echo "login, shell, exec service used && setting good" >> $RESULT_FILE 2>&1
			echo "PASS" >> $RESULT_FILE 2>&1
		fi
	else
		echo "login, shell, exec service used && setting bad" >> $RESULT_FILE 2>&1
		echo "FAIL" >> $RESULT_FILE 2>&1
	fi
fi
echo "[ U-17 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-17 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################
# -  u-18
##############################################

echo "[ U-18 ] : CHECK"
echo "==========[ U-18 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

get_cmd1=`cat /etc/hosts.deny | egrep -v '(^#|^$)'`
get_cmd2=`cat /etc/hosts.allow | egrep -v '(^#|^$)'`

if [ "$get_cmd1" = "" ] && [ "$get_cmd2" = "" ]; then
        echo "service not used" >> $RESULT_FILE 2>&1
        echo "PASS" >> $RESULT_FILE 2>&1
else 
	echo "service used" >> $RESULT_FILE 2>&1
	echo "FAIL" >> $RESULT_FILE 2>&1
fi

echo "[ U-18 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-18 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1



##############################################
# -  u-19
##############################################
echo "[ U-19 ] : CHECK"
echo "==========[ U-19 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

get_finger=`ls /etc/xinetd.d/finger 2>/dev/null`
ls /etc/xinetd.d/finger >> $RESULT_FILE 2>&1

if [ "$get_finger" = "" ]; then
        echo "Finger service not used" >> $RESULT_FILE 2>&1
        echo "PASS" >> $RESULT_FILE 2>&1
else
        echo "Finger service used" >> $RESULT_FILE 2>&1
        echo "FAIL" >> $RESULT_FILE 2>&1
fi

echo "[ U-19 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-19 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-20
##############################################
echo "[ U-20 ] : CHECK"
echo "==========[ U-20 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

FTP=1
vsftp_flag=0

echo "FTP Process Check" >> $RESULT_FILE 2>&1
get_ps=`ps -ef | grep -v 'grep' | grep 'ftpd' | grep -v 'tftp'`
if [ "$get_ps" != "" ]; then
	echo "$get_ps" >> $RESULT_FILE 2>&1
	if [ "`echo \"$get_ps\" | grep 'vsftp'`" != "" ]; then
		vsftp_flag=1
	fi
else
	echo "Not Found Process" >> $RESULT_FILE 2>&1
fi
echo "" >> $RESULT_FILE 2>&1

echo "FTP Service Check" >> $RESULT_FILE 2>&1
if [ "$systemctl_cmd" != "" ]; then
	get_service=`$systemctl_cmd list-units --type service | grep 'ftpd\.service' | sed -e 's\^ *//g' -e 's/^	*//g' | tr -s " \t"`
	if [ "$get_service" != "" ]; then
		echo "$get_service" >> $RESULT_FILE 2>&1
	else
		echo "Not Found Service" >> $RESULT_FILE 2>&1
	fi
else
	echo "Not Found systemctl Command" >> $RESULT_FILE 2>&1
fi
echo "" >> $RESULT_FILE 2>&1

echo " FTP Port Check" >> $RESULT_FILE 2>&1
if [ "$port_cmd" != "" ]; then
	get_port=`$port_cmd -na | grep "tcp" | grep "LISTEN" | grep ':21[ \t]'`
	if [ "$get_port" != "" ]; then
		echo "$get_port" >> $RESULT_FILE 2>&1
	else
		echo "Not Found Port" >> $RESULT_FILE 2>&1
	fi
else
	echo "Not Found Port Command" >> $RESULT_FILE 2>&1
fi
echo "" >> $RESULT_FILE 2>&1

if [ "$get_ps" != "" ] || [ "$get_service" != "" ] || [ "$get_port" != "" ]; then
	if [ $vsftp_flag -eq 0 ]; then
		if [ -f "/etc/passwd" ]; then
			user_chk=`cat /etc/passwd | grep ftp`
			if [ "$user_chk" != "" ]; then
				FTP=0
			fi
		fi
	else
		if [ -f "/etc/vsftpd/vsftpd.conf" ]; then
			conf_chk=`cat "/etc/vsftpd/vsftpd.conf" | grep -v '^#' | grep 'anonymous_enable'`
			echo "/etc/vsftpd/vsftpd.conf" >> $RESULT_FILE 2>&1
		elif [ -f "/etc/vsftpd.conf" ]; then
			conf_chk=`cat "/etc/vsftpd.conf" | grep -v '^#' | grep 'anonymous_enable'`
			echo "/etc/vsftpd.conf" >> $RESULT_FILE 2>&1
		fi
		if [ "$conf_chk" != "" ]; then
			conf_chk_tmp=`echo "$conf_chk" | awk -F"=" '{print $2}' | grep -i 'no'`
			echo "anonymous_enable=YES" >> $RESULT_FILE 2>&1
			if [ "$conf_chk_tmp" = "" ]; then
				FTP=0
			fi
		fi
	fi
fi

if [ $FTP -eq 1 ]; then
	echo "Pass" >> $RESULT_FILE 2>&1
else
	echo "Fail" >> $RESULT_FILE 2>&1
fi


echo "[ U-20 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-20 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################
# -  u-21
##############################################
echo "[ U-21 ] : CHECK"
echo "==========[ U-21 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

get_r=`find /usr/share/doc -name rsh-server 2>/dev/null |wc -l`

if [ "$get_r" = 0 ]; then
        echo "r service is disable" >> $RESULT_FILE 2>&1
        echo "PASS" >> $RESULT_FILE 2>&1
else
       	echo "r service is enable" >> $RESULT_FILE 2>&1
        echo "FAIL" >> $RESULT_FILE 2>&1
fi

echo "[ U-21 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-21 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################
# -  u-22
##############################################

echo "[ U-22 ] : CHECK"
echo "==========[ U-22 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

get_usercron=`ls -l /usr/bin/crontab 2>/dev/null | grep root | wc -l`
if [ $get_usercron = 0 ]; then
	echo "/usr/bin/crontab : file owner is not root" >> $RESULT_FILE 2>&1
	cnt=$((cnt+=1))
else
	echo "/usr/bin/crontab : file owner is root" >> $RESULT_FILE 2>&1
fi

get_usercron_perm=`ls -l /usr/bin/crontab | awk '{print $1}'`

if [ "$get_usercron_perm" = "-rw-r-x---" ]; then
	echo "/usr/bin/crontab : file permission is 750" >> $RESULT_FILE 2>&1  
else
	echo "/usr/bin/crontab : file permission is not 750" >> $RESULT_FILE 2>&1
	cnt=$((cnt+=1))
fi

get_etccron=`ls -l /etc/crontab | grep root | wc -l`
if [ $get_etccron = 0 ]; then
        echo "/etc/crontab : file owner is not root" >> $RESULT_FILE 2>&1
		cnt=$((cnt+=1))
else
        echo "/etc/crontab : file owner is root" >> $RESULT_FILE 2>&1
fi

get_etccron_perm=`ls -l /etc/crontab | awk '{print $1}'`
if [ "$get_etccron_perm" = "-rw-r-----" ]; then
        echo "/etc/crontab : file permission is 640" >> $RESULT_FILE 2>&1
else
        echo "/etc/crontab : file permission is not 640" >> $RESULT_FILE 2>&1
        cnt=$((cnt+=1))
fi


if [ $cnt -eq 0 ]; then
	echo "PASS" >> $RESULT_FILE 2>&1
else
	echo "FAIL" >> $RESULT_FILE 2>&1
fi

echo "[ U-22 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-22 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################
# -  u-23
##############################################
echo "[ U-23 ] : CHECK"
echo "==========[ U-23 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

check_cmd=`ls /etc/xinetd.d/* 2>/dev/null`
ls /etc/xinetd.d/* >> $RESULT_FILE 2>&1
if [ "$check_cmd" = "" ]; then
	echo "/etc/xinetd.d dosen't exist" >> $RESULT_FILE 2>&1
	echo "PASS" >> $RESULT_FILE 2>&1
else
	cnt=0
	get_echo=`cat /etc/xinetd.d/echo | grep disable | awk -F "=" '{print $2}' | grep yes | wc -l`
	if [ "$get_echo" -ne 2 ]; then
		echo "echo service is enabled"
		cnt=$((cnt+=1))
	else
		echo "echo service is disabled"
	fi

	get_discard=`cat /etc/xinetd.d/discard | grep disable | awk -F "=" '{print $2}' | grep yes | wc -l`
	if [ "$get_discard" -ne 2 ]; then
		echo "discard service is enabled"
		cnt=$((cnt+=1))
	else
		echo "discard service is disabled"
	fi

	get_daytime=`cat /etc/xinetd.d/daytime | grep disable | awk -F "=" '{print $2}' | grep yes | wc -l`
	if [ "$get_daytime" -ne 2 ]; then
		echo "daytime service is enabled"
		cnt=$((cnt+=1))
	else
		echo "daytime service is disabled"
	fi

	get_chargen=`cat /etc/xinetd.d/chargen | grep disable | awk -F "=" '{print $2}' | grep yes | wc -l`
	if [ "$get_chargen" -ne 2 ]; then
		echo "chargen service is enabled"
		cnt=$((cnt+=1))
	else
		echo "chargen service is disabled"
	fi

	if [ "$cnt" -eq 0 ]; then
        	echo "PASS" >> $RESULT_FILE 2>&1
	else
        	echo "FAIL" >> $RESULT_FILE 2>&1
	fi
fi

echo "[ U-23 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-23 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################
# -  u-24
##############################################
echo "[ U-24 ] : CHECK"
echo "==========[ U-24 START ]" >> $RESULT_FILE 2>&1

get_ps=`ps -ef | grep -v 'grep' | egrep '\[nfsd\]|\[lockd\]|\[statd\]'`
echo "NFS Process Check" >> $RESULT_FILE 2>&1
if [ "$get_ps" != "" ]; then
	echo "$get_ps" >> $RESULT_FILE 2>&1
else
	echo "Not Found Process" >> $RESULT_FILE 2>&1
fi

get_rpcinfo=`rpcinfo -p 2>/dev/null | egrep 'nfs|nlockmgr|status'`
echo "NFS Rpcinfo Check" >> $RESULT_FILE 2>&1
if [ "$get_rpcinfo" != "" ]; then
	echo "$get_rpcinfo" >> $RESULT_FILE 2>&1
else
	echo "Not Found rpcinfo" >> $RESULT_FILE 2>&1
fi

if [ "$get_ps" != "" ] || [ "$get_rpcinfo" != "" ]; then
	echo "Fail" >> $RESULT_FILE 2>&1
else
	echo "Pass" >> $RESULT_FILE 2>&1
fi

echo "[ U-24 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-24 END ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-25
##############################################
echo "[ U-25 ] : CHECK"
echo "==========[ U-25 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

get_export=`cat /etc/exports | grep -v "^#" | grep insecure | wc -w`
cat /etc/exports >> $RESULT_FILE 2>&1
if [ "$get_export" != 0 ];then
	echo "NFS service used" >> $RESULT_FILE 2>&1
	echo "FAIL" >> $RESULT_FILE 2>&1
else
	echo "/etc/exports not used" >> $RESULT_FILE 2>&1
	echo "PASS" >> $RESULT_FILE 2>&1
fi

echo "[ U-25 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-25 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################
# -  u-26
##############################################
echo "[ U-26 ] : CHECK"
echo "==========[ U-26 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

get_automountd=`ps -ef | grep automount | wc -l`

ps -ef | grep automount  >> $RESULT_FILE 2>&1
if [ "$get_automountd" = 0 ]; then
	echo "automountd service is disabled" >> $RESULT_FILE 2>&1
	echo "PASS" >> $RESULT_FILE 2>&1
else 
	echo "automountd service is enabled" >> $RESULT_FILE 2>&1
	echo "FAIL" >> $RESULT_FILE 2>&1
fi

echo "[ U-26 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-26 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################
# -  u-27
##############################################
echo "[ U-27 ] : CHECK"
echo "==========[ U-27 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

get_rpc=`cat /etc/xinetd.d/finger 2>/dev/null | wc -l`

if [ "$get_rpc" = 0 ]; then
        echo "RPC service is disabled" >> $RESULT_FILE 2>&1
        echo "PASS" >> $RESULT_FILE 2>&1
else
        echo "RPC service is enabled" >> $RESULT_FILE 2>&1
        echo "FAIL" >> $RESULT_FILE 2>&1
fi


echo "[ U-27 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-27 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################
# -  u-28
##############################################
echo "[ U-28 ] : CHECK"
echo "==========[ U-28 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

get_nis=`ps -ef | egrep "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated" | grep -v grep`

if [ "$get_nis" = "" ]; then
	echo "NIS service is disabled" >> $RESULT_FILE 2>&1
	echo "PASS" >> $RESULT_FILE 2>&1
else
	echo "NIC service is enabled" >> $RESULT_FILE 2>&1
	Echo "FAIL" >> $RESULT_FILE 2>&1
fi

echo "[ U-28 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-28 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################
# -  u-29
##############################################
echo "[ U-29 ] : CHECK"
echo "==========[ U-29 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

get_cmd=`ps -ef | egrep "tftp|talk|ntalk" | grep -v grep`
if [ "$get_cmd" = "" ]; then
	echo "tftp, talk, ntalk servie doesn't used" >> $RESULT_FILE 2>&1
	echo "PASS" >> $RESULT_FILE 2>&1
else
	echo "tftp, talk, ntalk service used" >> $RESULT_FILE 2>&1
	echo "FAIL" >> $RESULT_FILE 2>&1
fi

echo "[ U-29 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-29 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-30 Sendmail 버전 점검 
#############################################################################################
echo "[ U-30 ] : Check"
echo "=======================[U-30 Sendmail 버전 점검 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
echo "1. Sendmail 서비스 실행 여부 점검" >> $RESULT_FILE 2>&1
mail_ps=`ps -ef | grep -v "sendmail"`
if [ "$mail_ps" != "" ]; then
        echo "$mail_ps" >> $RESULT_FILE 2>&1
        send_flag=2
else
        echo "- NOT Found Sendmail Service" >> $RESULT_FILE 2>&1
        send_flag=1
fi
echo "" >> $RESULT_FILE 2>&1

echo "2. Sendmail 버전 점검" >> $RESULT_FILE 2>&1
send_ver=`telnet localhost 25 2>/dev/null`
if [ "$send_ver" != "" ]; then
        echo "$send_ver" >> $RESULT_FILE 2>&1
        send_flag=0
else
        echo "- NOT Found Sendmail" >> $RESULT_FILE 2>&1
        send_flag=1
fi
echo "" >> $RESULT_FILE 2>&1

# 취약: 0, 양호: 1, 검토: 2
if [ $send_flag -eq 1 ]; then
        echo "result : 양호" >> $RESULT_FILE 2>&1
elif [ $send_flag -eq 0 ]; then
        echo "result : 취약" >> $RESULT_FILE 2>&1
elif [ $send_flag -eq 2 ]; then
        echo "result : 검토" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=======================[U-30 Sendmail 버전 점검 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-31 스팸 메일 릴레이 제한 
#############################################################################################
echo "[ U-31 ] : Check"
echo "=======================[U-31 스팸 메일 릴레이 제한 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
echo "1. SMTP 서비스 사용 여부 확인" >> $RESULT_FILE 2>&1
smtp_ps=`ps -ef | grep sendmail | grep -v "grep"`
if [ "$smtp_ps" != "" ]; then
        echo "$smtp_ps" >> $RESULT_FILE 2>&1
        #릴레이 제한 옵션 확인
        echo `cat /etc/mail/sendmail.cf | grep "R$\&" | grep "Relaying denied"` >> $RESULT_FILE 2>&1
        smtp_flag=0
else
        echo "- NOT Found SMTP Service" >> $RESULT_FILE 2>&1
        smtp_flag=1
fi
echo "" >> $RESULT_FILE 2>&1

# 취약: 0, 양호: 1, 검토: 2
if [ $smtp_flag -eq 1 ]; then
        echo "result : 양호" >> $RESULT_FILE 2>&1
elif [ $smtp_flag -eq 0 ]; then
        echo "result : 취약" >> $RESULT_FILE 2>&1
elif [ $smtp_flag -eq 2 ]; then
        echo "result : 검토" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=======================[U-31 스팸 메일 릴레이 제한 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-32 일반사용자의 Sendmail 실행 방지
#############################################################################################
echo "[ U-32 ] : Check"
echo "=======================[U-32 일반사용자의 Sendmail 실행 방지 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
echo "1. SMTP 서비스 사용 여부 확인" >> $RESULT_FILE 2>&1
smtp_ps=`ps -ef | grep sendmail | grep -v "grep"`
if [ "$smtp_ps" != "" ]; then
        echo "Service State : YES" >> $RESULT_FILE 2>&1
        echo "$smtp_ps" >> $RESULT_FILE 2>&1
        #restrictqrun 옵션 확인
        echo `grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions | grep restrictqrun | wc -l` >> $RESULT_FILE 2>&1
        smtp_flag=0
else
        echo "Service State : NO" >> $RESULT_FILE 2>&1
        echo "- NOT Found SMTP Service" >> $RESULT_FILE 2>&1
        smtp_flag=1
fi

echo "" >> $RESULT_FILE 2>&1
echo "2. Sendmail 실행 파일 권한 확인" >> $RESULT_FILE 2>&1
send_path="/usr/sbin/sendmail"
if [[ "$(ls -l $send_path)" =~ "-rwxr-sr-x" ]]; then
        echo "- Sendmail 실행 파일 권한 설정: 올바름" >> $RESULT_FILE 2>&1
        smtp_flag=1
else
        echo "- Sendmail 실행 파일 권한 설정: 부적절함" >> $RESULT_FILE 2>&1
        smtp_flag=0
fi

echo "" >> $RESULT_FILE 2>&1

# 취약: 0, 양호: 1, 검토: 2
if [ $smtp_flag -eq 1 ]; then
        echo "result : 양호" >> $RESULT_FILE 2>&1
elif [ $smtp_flag -eq 0 ]; then
        echo "result : 취약" >> $RESULT_FILE 2>&1
elif [ $smtp_flag -eq 2 ]; then
        echo "result : 검토" >> $RESULT_FILE 2>&1
fi

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-33 DNS 보안 버전 패치
#############################################################################################
echo "[ U-33 ] : Check"
echo "=======================[U-33 DNS 보안 버전 패치 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
echo "1. Sendmail 서비스 실행 여부 점검" >> $RESULT_FILE 2>&1
mail_ps=`ps -ef | grep named`
if [ "$mail_ps" != "" ]; then
        echo "$mail_ps" >> $RESULT_FILE 2>&1
        mail_m=`named -v 2>/dev/null`
        if [ "$mail_m" != "" ]; then
                echo "$mail_m" >> $RESULT_FILE 2>&1
                mail_flag=0
        else
                mail_flag=2
        fi
else
        echo "- NOT Found Sendmail Service" >> $RESULT_FILE 2>&1
        mail_flag=1
fi
echo "" >> $RESULT_FILE 2>&1
# 취약: 0, 양호: 1, 검토: 2
if [ $mail_flag -eq 1 ]; then
        echo "result : 양호" >> $RESULT_FILE 2>&1
elif [ $mail_flag -eq 0 ]; then
        echo "result : 취약" >> $RESULT_FILE 2>&1
elif [ $mail_flag -eq 2 ]; then
        echo "result : 검토" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=======================[U-33 DNS 보안 버전 패치 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-34 DNS Zone Transfer 설정
#############################################################################################
echo "[ U-34 ] : Check"
echo "=======================[U-34 DNS Zone Transfer 설정 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

DNS=1
get_ps=`ps -ef | grep -v 'grep' |grep 'named'`
echo "1. DNS Service Process" >> $RESULT_FILE 2>&1
if [ "$get_ps" != "" ]; then
    echo "$get_ps" >> $RESULT_FILE 2>&1
else
    echo "- Not Found DNS Service Process" >> $RESULT_FILE 2>&1
fi


if [ -f "/etc/named.conf" ] && [ "$get_ps" != "" ]; then
        first=`cat /etc/named.conf | sed -e 's/^ *//g' -e 's/^  *//g' | egrep -v '^$|^//|^#'`
        second=`echo "$first" | awk -F"\n" 'BEGIN{count=0} { for(i=1;i<=NF;i++) { if($i ~ /\/\*/) count=1; if(count==0) print $i; if($i ~ /\*\//) count=0; }}'`
        result=`echo "$second" | awk 'BEGIN{count=0} { for(i=1;i<=NF;i++) { if($i ~ /allow-transfer/) count=1; if(count==1) printf "%s\n",$i; if(count==1 && $i ~ /}/) count=0; }}'`

        echo "" >> $RESULT_FILE 2>&1
        echo "$result" >> $RESULT_FILE 2>&1
        if [ "$result" = "" ] || [ "`echo \"$result\" | grep \"any;\"`" != "" ]; then
                DNS=0
        fi
fi

echo "" >> $RESULT_FILE 2>&1
if [ $DNS -eq 1 ]; then
    echo "result : 양호" >> $RESULT_FILE 2>&1
else
    echo "result : 취약" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=======================[U-34 DNS Zone Transfer 설정 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-35 웹서비스 디렉토리 리스팅 제거
#############################################################################################
echo "[ U-35 ] : Check"
echo "=======================[U-35 웹서비스 디렉토리 리스팅 제거 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

DIR=1
dir_ps=`ps -ef | grep named | grep -v "grep"`
opt_chk=`cat /etc/apache2/apache2.conf 2>/dev/null | grep -v "^#" | grep Options | egrep "Indexes" | wc -l`
echo "1. apache2 프로세스가 실행 중인지 검사" >> $RESULT_FILE 2>&1
if [ "$dir_ps" != "" ]; then
        echo "$dir_ps" >> $RESULT_FILE 2>&1
        DIR=2
else
        echo "- Not Found Web Service Directory Process" >> $RESULT_FILE 2>&1
        DIR=1
fi

echo "" >> $RESULT_FILE 2>&1
echo "2. Indexes 체크" >> $RESULT_FILE 2>&1
if [ "$opt_chk" != "0" ]; then
        echo "- Indexes : YES" >> $RESULT_FILE 2>&1
        DIR=0
elif [ "$opt_chk" = "0" ]; then
        echo "- Indexes : NO" >> $RESULT_FILE 2>&1
        DIR=1
fi
echo "" >> $RESULT_FILE 2>&1
if [ $DIR -eq 1 ]; then
    echo "result : 양호" >> $RESULT_FILE 2>&1
elif [ $DIR -eq 2 ]; then
    echo "result : 검토" >> $RESULT_FILE 2>&1
elif [ $DIR -eq 0 ]; then
    echo "result : 취약" >> $RESULT_FILE 2>&1
fi

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-36 웹서비스 웹 프로세스 권한 제한
#############################################################################################
echo "[ U-36 ] : Check"
echo "=======================[U-36 웹서비스 웹 프로세스 권한 제한 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
web_ps=`ps -ef | grep httpd | grep -v "grep" | wc -l`

WEBB=1
echo "1. Process Check" >> $RESULT_FILE 2>&1
if [ "$web_ps" != "0" ]; then
        echo `ps -ef | grep httpd` >> $RESULT_FILE 2>&1
        WEBB=2
        echo "" >> $RESULT_FILE 2>&1
        echo ">> Line Number(where is grep) : $web_ps" >> $RESULT_FILE 2>&1
else
        echo "- Not Found Web Process Access" >> $RESULT_FILE 2>&1
        WEBB=1
fi

echo "" >> $RESULT_FILE 2>&1
if [ $WEBB -eq 1 ]; then
        echo "result : 양호" >> $RESULT_FILE 2>&1
elif [ $WEBB -eq 2 ]; then
        echo "result : 검토" >> $RESULT_FILE 2>&1
elif [ $WEBB -eq 0 ]; then
        echo "result : 취약" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=======================[U-36 웹서비스 웹 프로세스 권한 제한 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-37 웹서비스 상위 디렉토리 접근 금지
#############################################################################################i
echo "[ U-37 ] : Check"
echo "=======================[U-37 웹서비스 상위 디렉토리 접근 금지 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
opt_chk=`cat /usr/local/apache2/conf/httpd.conf 2>/dev/null | grep -v "^#" | grep AllowOverride | grep -i "none" | wc -l`
ls_chk=`ls /usr/local/apache2/conf/httpd.conf 2>/dev/null`
CHK=1

echo "1. Apache2 File Check" >> $RESULT_FILE 2>&1
if [ "$ls_chk" != "" ]; then
        echo "- Apache2 File : exist" >> $RESULT_FILE 2>&1
        echo "" >> $RESULT_FILE 2>&1
        CHK=2
        echo "2. AllowOverride Check" >> $RESULT_FILE 2>&1
        if [ "$opt_chk" != "" ]; then
                echo "- AllowOverride - none : YES" >> $RESULT_FILE 2>&1
                CHK=0
        else
                echo "- AllowOverride - none : NO" >> $RESULT_FILE 2>&1
                CHK=1
        fi
else
        echo "- Not Found Apache2 File" >> $RESULT_FILE 2>&1
        CHK=1
fi
echo "" >> $RESULT_FILE 2>&1
if [ $CHK -eq 1 ]; then
        echo "result : 양호" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 2 ]; then
        echo "result : 검토" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 0 ]; then
        echo "result : 취약" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=======================[U-37 웹서비스 상위 디렉토리 접근 금지 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-38 웹서비스 불필요한 파일 제거
#############################################################################################i
echo "[ U-38 ] : Check"
echo "=======================[U-38 웹서비스 불필요한 파일 제거 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
CHK=1

find_file=`find / -name manual 2>/dev/null`

echo "1. Web Service unnecessary file" >> $RESULT_FILE 2>&1
if [ "${find_file:(-6)}" = "manual" ]; then
        echo "$find_file" >> $RESULT_FILE 2>&1
        echo "- Unnecessary file : exist" >> $RESULT_FILE 2>&1
        CHK=0
else
        echo "- Not Found unnecessary file" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
if [ $CHK -eq 1 ]; then
        echo "result : 양호" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 2 ]; then
        echo "result : 검토" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 0 ]; then
        echo "result : 취약" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=======================[U-38 웹서비스 불필요한 파일 제거 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-39 웹서비스 링크 사용금지
#############################################################################################i
echo "[ U-39 ] : Check"
echo "=======================[U-39 웹서비스 링크 사용금지 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
CHK=1

ls_chk=`ls /usr/local/apache2/conf/httpd.conf 2>/dev/null`
opt_chk=`cat /usr/local/apache2/conf/httpd.conf 2>/dev/null | grep "^#" | grep Options | grep -v - | grep -i "FollowSysLinks" | wc -l`
echo "1. Apache2 File Check" >> $RESULT_FILE 2>&1
if [ "$ls_chk" != "" ]; then
        echo "- Apache2 File : exist" >> $RESULT_FILE 2>&1
        echo "" >> $RESULT_FILE 2>&1
        CHK=2
        echo "2. FollowSymLinks Check" >> $RESULT_FILE 2>&1
        if [ "$opt_chk" != "0" ]; then
                echo "- FollowSymLinks : YES" >> $RESULT_FILE 2>&1
                CHK=0
        else
                echo "- FollowSymLinks : NO" >> $RESULT_FILE 2>&1
                CHK=1
        fi
else
        echo "- Not Found Apache2 File" >> $RESULT_FILE 2>&1
        CHK=1
fi

echo "" >> $RESULT_FILE 2>&1
if [ $CHK -eq 1 ]; then
        echo "result : 양호" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 2 ]; then
        echo "result : 검토" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 0 ]; then
        echo "result : 취약" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=======================[U-39 웹서비스 링크 사용금지 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-40 웹서비스 파일 업로드 및 다운로드 제한
#############################################################################################i
echo "[ U-40 ] : Check"
echo "=======================[U-40 웹서비스 파일 업로드 및 다운로드 제한 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
CHK=1

ls_chk=`ls /usr/local/apache2/conf/httpd.conf 2>/dev/null`
opt_chk=`cat /usr/local/apache2/conf/httpd.conf 2>/dev/null | grep -v "^#" | grep -i "LimitRequestBody" | wc -l`

echo "1. Apache2 File Check" >> $RESULT_FILE 2>&1
if [ "$ls_chk" != "" ]; then
        echo "- Apache2 File : exist" >> $RESULT_FILE 2>&1
        echo "" >> $RESULT_FILE 2>&1
        CHK=2
        echo "2. LimitRequestBody Check" >> $RESULT_FILE 2>&1
        if [ "$opt_chk" = "0" ]; then
                echo "- LimitRequestBody : NO" >> $RESULT_FILE 2>&1
                echo "- YOU NEED ADD >>LimitRequestBody<<" >> $RESULT_FILE 2>&1
                CHK=0
        else
                echo "- LimitRequestBody : YES" >> $RESULT_FILE 2>&1
                CHK=1
        fi
else
        echo "- Not Found Apache2 File" >> $RESULT_FILE 2>&1
        CHK=1
fi

echo "" >> $RESULT_FILE 2>&1
if [ $CHK -eq 1 ]; then
        echo "result : 양호" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 2 ]; then
        echo "result : 검토" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 0 ]; then
        echo "result : 취약" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=======================[U-40 웹서비스 파일 업로드 및 다운로드 제한 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-41 웹서비스 영역의 분리
#############################################################################################i
echo "[ U-41 ] : Check"
echo "=======================[U-41 웹서비스 영역의 분리 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
CHK=1

ls_chk=`ls /usr/local/apache2/conf/httpd.conf 2>/dev/null`
opt_chk=`cat /usr/local/apache2/conf/httpd.conf 2>/dev/null | grep -v "^#" | grep DocumentRoot | awk -F " " '{print $2}' | tr -d " "`
opt_count=`cat /usr/local/apache2/conf/httpd.conf 2>/dev/null | grep -v "^#" | grep DocumentRoot | wc -l`
check_list=("/usr/local/apache2/htdocs" "/var/www/html" "/usr/local/apache/htdocs")
count=0

echo "1. Apache2 File Check" >> $RESULT_FILE 2>&1
if [ "$ls_chk" != "" ]; then
        echo "- Apache2 File : exist" >> $RESULT_FILE 2>&1
        echo "" >> $RESULT_FILE 2>&1
        CHK=2
        echo "2. DocumentRoot Check" >> $RESULT_FILE 2>&1
        if [ "$opt_count" != "0" ]; then
                echo "- DocumentRoot : YES" >> $RESULT_FILE 2>&1
                echo "- YOU HAVE DocumentRoot" >> $RESULT_FILE 2>&1
                CHK=2
        fi

        echo "" >> $RESULT_FILE 2>&1
        echo "2-1.기타 디렉터리 설정 Check" >> $RESULT_FILE 2>&1
        for path in ${check_list[@]}
        do
                if [ "$opt_chk" = "$path" ]; then
                        count=`expr $count + 1 `
                fi
        done
        if [ $count = 0 ]; then
                echo "- No Problem" >> $RESULT_FILE 2>&1
                CHK=1
        else
                echo "- YOU NEED TO CHANGE ANOTHER DIRECTORY" >> $RESULT_FILE 2>&1
                CHK=0
        fi
else
        echo "- Not Found Apache2 File" >> $RESULT_FILE 2>&1
        CHK=1
fi

echo "" >> $RESULT_FILE 2>&1
if [ $CHK -eq 1 ]; then
        echo "result : 양호" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 2 ]; then
        echo "result : 검토" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 0 ]; then
        echo "result : 취약" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=======================[U-41 웹서비스 영역의 분리 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-44
##############################################

echo "[U-44] : Check"
echo "=====================[U-44 Prohibit UID Other Than '0' for root]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

users=`awk -F: '$3 == 0 {print $1}' /etc/passwd`

for user in $users; do
    if [ "$user" != "root" ]; then
        echo "Username: $user" >> $RESULT_FILE 2>&1
        echo "RESULT: chiyak" >> $RESULT_FILE 2>&1
    else
        echo "No users with UID other than '0' found."
        echo "RESULT: yangho" >> $RESULT_FILE 2>&1
    fi
done

if [ -z "$users" ]; then
    echo "No users with UID other than '0' found." >> $RESULT_FILE 2>&1
    echo "RESULT: yangho" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "================= [U-44 Prohibit UID Other Than '0' for root EnD]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
##############################################
# -  u-45
##############################################

echo "[U-45] : Check"
echo "=========[U-45 Root Account 'su' Limitation START]" >> $RESULT_FILE 2>&1

root_su=`cat /etc/pam.d/su |grep -v '#' |grep -v '^$' |grep 'auth required pam_wheel.so debug group=wheel'`
root_su2=`cat /etc/pam.d/su |grep -v '#' |grep -v '^$' |grep 'auth required pam_wheel.so use_uid'`

if [ "$root_su" = "" ] | [ "$root_su2" = "" ]; then
    echo "su is Limited" >> $RESULT_FILE 2>&1
    echo "RESULT: yangho" >> $RESULT_FILE 2>&1
else
    echo "$root_su / $root_su2" >> $RESULT_FILE 2>&1
    echo "RESULT: chwiyak" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=========[U-45 Root Account 'su' Limitation END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-46
##############################################
echo "[U-46] : Check"
echo "=========[U-46 Password Minimum Length START]" >> $RESULT_FILE 2>&1


PASSWD_FILE=/etc/login.defs

if [ -f $PASSWD_FILE ]; then
    PASS_LENGTH=`grep -E "^PASS_MIN_LEN" $PASSWD_FILE | awk '{print $2}'`

    if [ -z "$PASS_LENGTH" ]; then
        echo "No minimum password length set in $PASSWD_FILE file." >> $RESULT_FILE 2>&1
        echo "RESULT: chwiyak" >> $RESULT_FILE 2>&1
    else
        echo "`grep -E "^PASS_MIN_LEN" $PASSWD_FILE`" >> $RESULT_FILE 2>&1
        if [ "$PASS_LENGTH" -lt 8 ]; then
           echo "Minimum password length is less than 8 characters" >> $RESULT_FILE 2>&1
		echo "RESULT: chwiyak" >> $RESULT_FILE 2>&1
        else
            echo "Minimum password length is set to $PASS_LENGTH characters" >> $RESULT_FILE 2>&1
            echo "RESULT: yangho" >> $RESULT_FILE 2>&1
        fi
    fi
else
    echo "Password file $PASSWD_FILE not found." >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=========[U-46 Password Minimum Length END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-47
##############################################
echo "[U-47] : Check"
echo "=========[U-47 Password Expiry Date START]" >> $RESULT_FILE 2>&1

PASS_MAX_DAYS=`cat /etc/login.defs | grep "^PASS_MAX_DAYS" | awk '{print $2}'`
if [ -z "$PASS_MAX_DAYS" ] ; then
    echo "Pass_max_days is not configured." >> $RESULT_FILE 2>&1
    echo "RESULT: chwiyak" >> $RESULT_FILE 2>&1
else
    echo "`cat /etc/login.defs | grep "^PASS_MAX_DAYS"`" >> $RESULT_FILE 2>&1
    echo "Pass_max_days is $PASS_MAX_DAYS days" >> $RESULT_FILE 2>&1

    if [ $PASS_MAX_DAYS -le 90 ] ; then
        echo "Pass_max_days is less than or equal to 90 days." >> $RESULT_FILE 2>&1
	  echo "RESULT: yangho" >> $RESULT_FILE 2>&1
    else
        echo "Pass_max_days is greater than 90 days." >> $RESULT_FILE 2>&1
        echo "RESULT: chwiyak" >> $RESULT_FILE 2>&1
    fi
fi

echo "" >> $RESULT_FILE 2>&1
echo "=========[U-47 Password Expiry Date END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-48
##############################################
echo "[U-48] : Check"
echo "=========[U-48 Password Minimum Age START]" >> $RESULT_FILE 2>&1

PASS_MIN_DAYS=`cat /etc/login.defs | grep "^PASS_MIN_DAYS" | awk '{print $2}'`
if [ -z "$PASS_MIN_DAYS" ] ; then
    echo "Pass_min_days is not configured." >> $RESULT_FILE 2>&1
    echo "RESULT: chwiyak" >> $RESULT_FILE 2>&1
else
    echo "`cat /etc/login.defs | grep "^PASS_MIN_DAYS"`" >> $RESULT_FILE 2>&1
    echo "Pass_min_days is $PASS_MIN_DAYS days" >> $RESULT_FILE 2>&1
    if [[ $PASS_MIN_DAYS -lt 1 ]]; then
        echo "Password minimum age is less than 1 day" >> $RESULT_FILE 2>&1
        echo "RESULT: chwiyak" >> $RESULT_FILE 2>&1
    else
        echo "Password minimum age is at least 1 day" >> $RESULT_FILE 2>&1
        echo "RESULT: yangho" >> $RESULT_FILE 2>&1
    fi
fi

echo "" >> $RESULT_FILE 2>&1
echo "=========[U-48 Password Minimum Age END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-49
##############################################
echo "[U-49] : Check"
echo "=========[U-49 Unnecessary Account Check START]" >> $RESULT_FILE 2>&1
count=0
# 예외 계정 목록을 설정합니다. 이 부분은 각 시스템에 맞게 수정해야 합니다.
unneccessary="lp|uucp|nuucp"

# 계정 정보를 가져와서 필요없는 계정을 찾습니다.
get_users=`cat /etc/passwd | awk -F: '{print $1}'`
for user in $get_users; do
    # 예외 계정은 제외합니다.
    if [[ $unneccessary =~ $user ]]; then
        echo "unneccessary user($user) exists" >> $RESULT_FILE 2>&1
        count=`expr $count + 1`
    fi
done

if [ $count -eq 0 ]; then
    echo "RESULT: yangho" >> $RESULT_FILE 2>&1
else
    echo "RESULT: chiyak" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=========[U-49 Unnecessary Account Check END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-50
##############################################
echo "[U-50] : Check"
echo "=========[U-50 Check START]" >> $RESULT_FILE 2>&1

CHK_GROUP=`cat /etc/group | grep "^root" | awk -F"," '{print $2}'`


if [ -n "$CHK_GROUP" ]; then
    echo "`cat /etc/group | grep "^root" | awk -F"," '{print $2}'`" >> $RESULT_FILE 2>&1
    echo "User(not root) is in admin group." >> $RESULT_FILE 2>&1
    echo "RESULT: chwiyak" >> $RESULT_FILE 2>&1
else
    echo "only root is in admin group" >> $RESULT_FILE 2>&1
    echo "RESULT: yangho" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=========[U-50 Check END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-51
##############################################

echo "[U-51] : Check"
echo "=====================[U-51 Prohibit Nonexistent GID for Accounts]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
count=0
groups=`cat /etc/group | awk -F: '{print $3}'`

for gid in $groups; do
    users=`cat /etc/passwd | awk -F: -v gid="$gid" '$4 == gid {print $1}'`
    if [ -z "$users" ]; then
        echo "GID: $gid" >> $RESULT_FILE 2>&1
        count=`expr $count + 1`
    fi
done
if [ $count -eq 0 ]; then
    echo "RESULT: yangho" >> $RESULT_FILE 2>&1
else
    echo "RESULT: chiyak" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "================= [U-51 Prohibit Nonexistent GID for Accounts EnD]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
##############################################
# -  u-52
##############################################
echo "[U-52] : Check"
echo "=========[U-52 Same UID Check START]" >> $RESULT_FILE 2>&1

echo "Same UID Check" >> $RESULT_FILE 2>&1

get_uid=`cat /etc/passwd | awk -F: '{print $3}' | sort | uniq -d`

if [ "$get_uid" != "" ]; then
    echo "Found Same UID: $get_uid" >> $RESULT_FILE 2>&1
    echo "RESULT: chwiyak" >> $RESULT_FILE 2>&1
else
    echo "No Same UID Found" >> $RESULT_FILE 2>&1
    echo "RESULT: yangho" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=========[U-52 Same UID Check END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-53
##############################################
echo "[U-53] : Check"
echo "=========[U-53 User Shell Check START]" >> $RESULT_FILE 2>&1
count=0

awk -F: '{print $1 " " $7}' /etc/passwd | while read user shell
do

  if [[ "$shell" == "/bin/bash" || "$shell" == "/bin/sh" || "$shell" == "/sbin/nologin" || "$shell" == "/usr/sbin/nologin" ]]
  then
    echo "$user : $shell" >> $RESULT_FILE 2>&1
  else
    echo "$user : $shell" >> $RESULT_FILE 2>&1
    count=`expr $count + 1 `
    
  fi
done

if [ $count -eq 0 ]; then
    echo "RESULT: yangho" >> $RESULT_FILE 2>&1
else
    echo "RESULT: chiyak" >> $RESULT_FILE 2>&1
fi


echo "" >> $RESULT_FILE 2>&1
echo "=========[U-53 User Shell Check END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-54
##############################################
echo "[U-54] : Check" 
echo "=====================[U-54 Session Timeout Configuration]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

# 세션 타임아웃 설정 파일
timeout_file="/etc/profile"
# 세션 타임아웃 설정 값
timeout_value=`grep -E "^TMOUT=" $timeout_file | awk -F'=' '{print $2}'`

if [ "$timeout_value" != "" ]; then
    echo "Session Timeout Configuration: $timeout_value seconds" >> $RESULT_FILE 2>&1
    if [ $timeout_value -le "600" ]; then
        echo "RESULT: yangho" >> $RESULT_FILE 2>&1
    else
        echo "session timeout value is too much" >> $RESULT_FILE 2>&1
        echo "RESULT: chwiyak" >> $RESULT_FILE 2>&1
    fi
else
    echo "Session Timeout Configuration: Not configured" >> $RESULT_FILE 2>&1
    echo "RESULT: chwiyak" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "================= [U-54 Session Timeout Configuration EnD]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-55
##############################################
echo "[U-55] : Check"
echo "=====================[U-55 hosts.lpd File Ownership and Permissions Check]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1



if [ -f "/etc/hosts.lpd" ]; then
    permission_val=`stat -c '%a' /etc/hosts.lpd`
    owner_val=`stat -c '%U' /etc/hosts.lpd`
    echo "permission is $permission_val and owner is $owner_val" >> $RESULT_FILE 2>&1
    owner_perm_val=`echo "$permission_val" | awk '{ print substr($0, 1, 1) }'`
    group_perm_val=`echo "$permission_val" | awk '{ print substr($0, 2, 1) }'`
    other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`
    if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -eq 0 ] && [ "$other_perm_val" -eq 0 ] && [ "$owner_val" = "root" ]; then
        echo "RESULT: yangho" >> $RESULT_FILE 2>&1
    else
        echo "RESULT: chiyak" >> $RESULT_FILE 2>&1
    fi

else
    echo "Not Found /etc/hosts.lpd" >> $RESULT_FILE 2>&1
    echo "RESULT: yangho" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "================= [U-55 hosts.lpd File Ownership and Permissions Check EnD]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-56
##############################################
echo "[U-56] : Check"
echo "=====================[U-56 UMASK Configuration Management Check]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

# UMASK 설정 확인
umask_value=`grep -E "^umask" /etc/profile 2>/dev/null | grep -v "^#" | awk '{print $2}'`
if [ -n "$umask_value" ]; then
    echo "UMASK Value: $umask_value" >> $RESULT_FILE 2>&1

    # 적절한 UMASK 설정 여부 확인
    if [ "$umask_value" -ge 022 ]; then
        echo "RESULT: yangho" >> $RESULT_FILE 2>&1
    else
        echo "RESULT: chiyak" >> $RESULT_FILE 2>&1
    fi
else
    echo "UMASK Value not found" >> $RESULT_FILE 2>&1
    echo "RESULT: chiyak" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "================= [U-56 UMASK Configuration Management Check EnD]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
##############################################
# -  u-57
##############################################
echo "[U-57] : Check"
echo "=====================[U-57 Home Directory Ownership and Permissions]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
count=0

users=`cat /etc/passwd | awk -F: '$7 != "/usr/sbin/nologin" {print $1}'`

for user in $users; do
    home_dir=`eval echo ~$user`
    if [ -d "$home_dir" ]; then
        echo "Home Directory: $home_dir" >> $RESULT_FILE 2>&1
        owner_val=`stat -c '%U' $home_dir`
        permission_val=`stat -c '%a' $home_dir`
        other_perm_val=`echo "$permission_val" | awk '{ print substr($0, 3, 1) }'`
        if [ "$other_perm_val" -eq 2 ] && [ "$other_perm_val" -eq 6 ] && [ "$other_perm_val" -eq 7 ] && [ "$owner_val" != "$user" ]; then
            echo "permission is $permission_val and owner is $owner_val" >> $RESULT_FILE 2>&1
            echo "chwiyak" >> $RESULT_FILE 2>&1
            count=`expr $count + 1 `
        else
            echo "permission is $permission_val and owner is $owner_val" >> $RESULT_FILE 2>&1
            
        fi

        echo "" >> $RESULT_FILE 2>&1
    fi
done

if [ $count -eq 0 ]; then
    echo "RESULT: yangho" >> $RESULT_FILE 2>&1
else
    echo "RESULT: chiyak" >> $RESULT_FILE 2>&1
fi

echo "================= [U-57 Home Directory Ownership and Permissions EnD]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-58
##############################################
echo "[U-58] : Check"
echo "=====================[U-58 Existence of Specified Home Directory]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
count=0
users=`cat /etc/passwd | awk -F: '$7 != "/usr/sbin/nologin" {print $1":"$6}'`

for user_info in $users; do
    IFS=":" read -r username home_dir <<< "$user_info"
    if [ -d "$home_dir" ] && [ "$home_dir" != "/" ] ; then
        echo "Username: $username" >> $RESULT_FILE 2>&1
        echo "Home Directory: $home_dir" >> $RESULT_FILE 2>&1
    else
        echo "Username: $username" >> $RESULT_FILE 2>&1
        echo "$home_dir is not Home Directory" >> $RESULT_FILE 2>&1
        echo "chwiyak" >> $RESULT_FILE 2>&1
        count=`expr $count + 1 `
    fi
    echo "" >> $RESULT_FILE 2>&1
done
if [ $count -eq 0 ]; then
    echo "RESULT: yangho" >> $RESULT_FILE 2>&1
else
    echo "RESULT: chiyak" >> $RESULT_FILE 2>&1
fi

echo "================= [U-58 Existence of Specified Home Directory EnD]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-59
##############################################
echo "[U-59] : Check"
echo "=====================[U-59 Search and Remove Hidden Files and Directories]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

TARGET_PATH="/home"  #### 검색 대상 경로 설정(/home 은 예시)####

hidden_files=`find "$TARGET_PATH" -type f -name ".*"`
hidden_dirs=`find "$TARGET_PATH" -type d -name ".*"`

if [ -n "$hidden_files" ]; then
    echo "Hidden Files:" >> $RESULT_FILE 2>&1
    echo "$hidden_files" >> $RESULT_FILE 2>&1


    echo "RESULT: chiyak" >> $RESULT_FILE 2>&1
else
    echo "No Hidden Files Found" >> $RESULT_FILE 2>&1
    echo "RESULT: yangho" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1

if [ -n "$hidden_dirs" ]; then
    echo "Hidden Directories:" >> $RESULT_FILE 2>&1
    echo "$hidden_dirs" >> $RESULT_FILE 2>&1


    echo "RESULT: chiyak" >> $RESULT_FILE 2>&1
else
    echo "No Hidden Directories Found" >> $RESULT_FILE 2>&1
    echo "RESULT: yangho" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "================= [U-59 Search and Remove Hidden Files and Directories EnD]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-60 ssh 원격접속 허용
#############################################################################################
echo "[ U-60 ] : Check"
echo "=======================[U-60 ssh 원격접속 허용 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

ssh_ps=`ps -ef | grep sshd | grep -v grep 2>/dev/null`
ssh_sv=`service start sshd 2>/dev/null`
ssh_sv2=`service start ssh 2>/dev/null`
CHK=1

check_ssh_connection() {
    echo "1. SSH Check" >> $RESULT_FILE 2>&1
    if [ "$ssh_ps" != "" ]; then
        echo "$ssh_ps" >> $RESULT_FILE 2>&1
        echo "- SSH Process Start" >> $RESULT_FILE 2>&1
        CHK=0
    else
        echo "- Not Found SSH Process" >> $RESULT_FILE 2>&1
        CHK=1
    fi

    echo "" >> $RESULT_FILE 2>&1
    echo "2. SSH Service" >> $RESULT_FILE 2>&1
    if [ "$ssh_sv" != "" ] || [ "$ssh_sv2" != "" ]; then
        echo "$ssh_sv" >> $RESULT_FILE 2>&1
        echo "$ssh_sv2" >> $RESULT_FILE 2>&1
        echo "- SSH Service Start" >> $RESULT_FILE 2>&1
        CHK=0
    else
        echo "- Not Found SSH Service" >> $RESULT_FILE 2>&1
        CHK=1
    fi
}

check_ssh_connection

echo "" >> $RESULT_FILE 2>&1
if [ $CHK -eq 1 ]; then
        echo "result : 양호" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 2 ]; then
        echo "result : 검토" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 0 ]; then
        echo "result : 취약" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=======================[U-60 ssh 원격접속 허용 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-61 ftp 서비스 확인
#############################################################################################
echo "[ U-61 ] : Check"
echo "=======================[U-61 ftp 서비스 확인 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
CHK=1
CHK2=1

ftp_ps=`ps -ef | egrep ftp 2>/dev/null`
ftp_ps2=`ps -ef | egrep "vsftpd|proftp" 2>/dev/null`

echo "1. 일반 ftp 서비스 비활성화 여부 확인" >> $RESULT_FILE 2>&1
if [ "$ftp_ps" != "" ]; then
        echo "$ftp_ps" >> $RESULT_FILE 2>&1
        echo "- FTP Service Start" >> $RESULT_FILE 2>&1
        CHK=2
else
        echo "- Not Found FTP Service" >> $RESULT_FILE 2>&1
        CHK=1
fi

echo "" >> $RESULT_FILE 2>&1
echo "2. vsftpd 또는 ProFTP 서비스 데몬 확인(vsftpd, proftpd 동작 SID 확인)" >> $RESULT_FILE 2>&1
if [ "$ftp_ps2" != "" ]; then
        echo "$ftp_ps2" >> $RESULT_FILE 2>&1
        echo "- vsftpd/ProFTP Service Demon Start" >> $RESULT_FILE 2>&1
        CHK2=0
else
        echo "- Not Found vsftpd/ProFTP Demon Service" >> $RESULT_FILE 2>&1
        CHK2=1
fi

sum=$(($CHK + $CHK2))

echo "" >> $RESULT_FILE 2>&1
if [ $sum -eq 1 ]; then
        echo "result : 양호" >> $RESULT_FILE 2>&1
elif [ $sum -eq 4 ]; then
        echo "result : 검토" >> $RESULT_FILE 2>&1
elif [ $sum -eq 2 ]; then
        echo "result : 검토2" >> $RESULT_FILE 2>&1
else
        echo "result : 취약" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=======================[U-61 ftp 서비스 확인 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-62 ftp 계정 shell 제한
#############################################################################################
echo "[ U-62 ] : Check"
echo "=======================[U-62 ftp 계정 shell 제한 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
CHK=1

chk_f=`cat /etc/passwd | grep ftp | awk -F: '{print $NF}' | awk -F/ '{print $NF}' 2>/dev/null`

echo "1. FTP Check" >> $RESULT_FILE 2>&1
if [ "$chk_f" = "nologin" ] || [ "$chk_f" = "false" ]; then
        echo "- It's OK" >> $RESULT_FILE 2>&1
        CHK=1
else
        echo "- WARNING" >> $RESULT_FILE 2>&1
        CHK=0
fi

echo "" >> $RESULT_FILE 2>&1
if [ $CHK -eq 1 ]; then
        echo "result : 양호" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 2 ]; then
        echo "result : 검토" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 0 ]; then
        echo "result : 취약" >> $RESULT_FILE 2>&1
fi

echo "" >> $RESULT_FILE 2>&1
echo "=======================[U-62 ftp 계정 shell 제한 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-63 ftpusers 파일 소유자 및 권한 설정
#############################################################################################
echo "[ U-63 ] : Check"
echo "=======================[U-63 ftpusers 파일 소유자 및 권한 설정 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
CHK=1

file_ct=`cat /etc/vsftpd/ftpusers >/dev/null 2>&1`
us_ps=`ps -ef | grep vsftpd | grep -v grep >/dev/null 2>&1`

echo "1. ftpusers Check" >> $RESULT_FILE 2>&1
if [ "$file_ct" != "" ]; then
        echo "$file_ct" >> $RESULT_FILE 2>&1
        CHK=2
else
        echo "- Not Found ftpusers file" >> $RESULT_FILE 2>&1
        CHK=1
fi

echo "" >> $RESULT_FILE 2>&1
chk2=`ls -al /etc/vsftpd/ftpusers >/dev/null 2>&1 | awk '{print $1}' | cut -c 2-` >> tmpp.log
echo "2. ftpusers Service Check2" >> $RESULT_FILE 2>&1
if [ -s tmpp.log ]; then
        echo "- You Need Check tmpp.log" >> $RESULT_FILE 2>&1
        CHK=0
else
        echo "- It's OK" >> $RESULT_FILE 2>&1
        CHK=1
fi
rm tmpp.log

echo "" >> $RESULT_FILE 2>&1
if [ $CHK -eq 1 ]; then
        echo "result : 양호" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 2 ]; then
        echo "result : 검토" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 0 ]; then
        echo "result : 취약" >> $RESULT_FILE 2>&1
fi
echo "" >> $RESULT_FILE 2>&1
echo "=======================[U-63 ftpusers 파일 소유자 및 권한 설정 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-64 ftpusers 파일 설정(FTP 서비스 root 계정 접근제한)
#############################################################################################
echo "[ U-64 ] : Check"
echo "=======================[U-64 ftpusers 파일 설정(FTP 서비스 root 계정 접근제한) START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
CHK=1
rt_ps=`ps -ef | grep ftp | grep -v grep >/dev/null 2>&1` >> tmpp.log
rt_ps2=`cat /etc/vsftpd/ftpusers >/dev/null 2>&1 | grep 'root' | grep -v '#'`

echo "1. FTP Check" >> $RESULT_FILE 2>&1
if [ -s tmpp.log ]; then
        echo "- FTP Service Start Now" >> $RESULT_FILE 2>&1
        CHK=0
else
        echo "- It's OK" >> $RESULT_FILE 2>&1
        CHK=1
fi
rm tmpp.log

echo "" >> $RESULT_FILE 2>&1
echo "2. Can ROOT?" >> $RESULT_FILE 2>&1
if [ "$rt_ps2" = "0" ]; then
        echo "- WARNING: You Can" >> $RESULT_FILE 2>&1
        CHK=0
else
        echo "- It's OK2" >> $RESULT_FILE 2>&1
        CHK=1
fi

echo "" >> $RESULT_FILE 2>&1
if [ $CHK -eq 1 ]; then
        echo "result : 양호" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 2 ]; then
        echo "result : 검토" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 0 ]; then
        echo "result : 취약" >> $RESULT_FILE 2>&1
fi
echo "" >> $RESULT_FILE 2>&1
echo "=======================[U-64 ftpusers 파일 설정(FTP 서비스 root 계정 접근제한) END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-65 at 서비스 권한 설정
#############################################################################################
# 수동진단 필요

#############################################################################################
# -주요 정보 통신 기반 시설 | 서비스 관리
# -U-66 SNMP 서비스 구동 점검
#############################################################################################
echo "[ U-66 ] : Check"
echo "=======================[U-66 SNMP 서비스 구동 점검 START]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1
CHK=1

sn_ps=`ps -ef | grep snmp`

echo "1. SNMP Service Check" >> $RESULT_FILE 2>&1
if [ "$sn_ps" != "" ]; then
        echo "$sn_ps" >> $RESULT_FILE 2>&1
        echo "- SNMP Service START" >> $RESULT_FILE 2>&1
        CHK=2
else
        echo "- Not Found SNMP Service" >> $RESULT_FILE 2>&1
        CHK=1
fi

echo "" >> $RESULT_FILE 2>&1
if [ $CHK -eq 1 ]; then
        echo "result : 양호" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 2 ]; then
        echo "result : 검토" >> $RESULT_FILE 2>&1
elif [ $CHK -eq 0 ]; then
        echo "result : 취약" >> $RESULT_FILE 2>&1
fi
echo "" >> $RESULT_FILE 2>&1
echo "=======================[U-66 SNMP 서비스 구동 점검 END]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-67
##############################################
echo "[ U-67 ] : CHECK"
echo "==========[ U-67 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

snmp_file=/etc/snmp/snmpd.conf
if [ -f $snmp_file ]; then
	get_snmp_pri=`cat $snmp_file | egrep public | grep -v '#'`
	get_snmp_pub=`cat $snmp_file | egrep private | grep -v '#'`
	if [ $get_snmp_pri != "" ] && [ $get_snmp_pub != "" ]; then
		echo "/etc/snmp/snmpd.conf exist" >> $RESULT_FILE 2>&1
		echo "SNMP Community name is public, private" >> $RESULT_FILE 2>&1
		echo "FAIL" >> $RESULT_FILE 2>&1
	else
		echo "/etc/snmp/snmpd.conf exist" >> $RESULT_FILE 2>&1
		echo "SNMP Community name is not public, private" >> $RESULT_FILE 2>&1
		echo "PASS" >> $RESULT_FILE 2>&1
	fi
else
	echo "/etc/snmp/snmpd.conf:No such file or directory" >> $RESULT_FILE 2>&1
	echo "/etc/snmp/snmpd.conf file not used or doesn't exist" >> $RESULT_FILE 2>&1
	echo "PASS" >> $RESULT_FILE 2>&1
fi

echo "[ U-67 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-67 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################
# -  u-68
##############################################
echo "[ U-68 ] : CHECK"
echo "==========[ U-68 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

get_file_motd=`cat /etc/motd`
get_file_issue=`cat /etc/issue.net | grep -i warning | grep -v grep`

cnt=0
if [ "$get_file_motd" = "" ]; then
	echo "/etc/motd : Alert message input required" >> $RESULT_FILE 2>&1
	cnt=$((cnt+1))
fi

if [ "$get_file_issue" = "" ]; then
	echo "/etc/issue.net : Alert message input required" >> $RESULT_FILE 2>&1
	cnt=$((cnt+1))
else
	echo "/etc/issue.net : Alert message entered" >> $RESULT_FILE 2>&1
fi

if [ "`ps -ef | grep ftp | grep -v grep`" != "" ]; then
	get_file_ftp=`cat /etc/vsftpd/vsftpd.conf | grep -i "ftpd_banner" | grep -v grep`
	if [ "$get_file_ftp" = "" ]; then
		echo "/etc/vsftpd/vsftpd.conf : Alert message input required" >> $RESULT_FILE 2>&1
		cnt=$((cnt+1))
	else
		echo "/etc/vsftpd/vsftpd.conf : Alert message enterd" >> $RESULT_FILE 2>&1
	fi
else
	echo "FTP not used" >> $RESULT_FILE 2>&1
fi

if [ "`ps -ef | grep sendmail | grep -v grep`" != "" ]; then
	get_file_smtp=`cat /etc/mail/sendmail.cf | grep -i "greetingmessage" | grep -v grep`
	if [ "$get_file_smtp" = "" ]; then
		echo "/etc/mail/sendmail.cf : Alert message input required" >> $RESULT_FILE 2>&1
		cnt=$((cnt+10))
	else
		echo "/etc/mail/sendmail.cf : Alert message enterd" >> $RESULT_FILE 2>&1
	fi
else
	echo "sendmail not used" >> $RESULT_FILE 2>&1
fi

if [ "`ps -ef | grep named | grep -v grep`" != "" ]; then
	get_file_dns=`cat /etc/named.conf | grep -i warning | grep -v grep`	
	if [ "$get_file_dns" = "" ]; then
        	echo "/etc/named.conf : Alert message input required" >> $RESULT_FILE 2>&1
        	cnt=$((cnt+1))
	fi
else
	echo "dns not used" >> $RESULT_FILE 2>&1
fi

if [ $cnt -eq 0 ]; then
	echo "PASS" >> $RESULT_FILE 2>&1
else
	echo "FAIL" >> $RESULT_FILE 2>&1
fi


echo "[ U-68 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-68 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1


##############################################
# -  u-69
##############################################
echo "[ U-69 ] : CHECK"
echo "==========[ U-69 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

ls -al /etc/exports >> $RESULT_FILE 2>&1
exports_permission=`stat -c '%a' /etc/exports`
exports_owner=`stat -c '%U' /etc/exports`
owner_perm_val=`echo "$exports_permission" | awk '{ print substr($0, 1, 1) }'`
group_perm_val=`echo "$exports_permission" | awk '{ print substr($0, 2, 1) }'`
other_perm_val=`echo "$exports_permission" | awk '{ print substr($0, 3, 1) }'`

echo "permission : $exports_permission" >> $RESULT_FILE 2>&1
echo "owner : $exports_owner" >> $RESULT_FILE 2>&1

if [ "$owner_perm_val" -le 6 ] && [ "$group_perm_val" -le 4 ] && [ "$other_perm_val" -le 4 ] && [ "$exports_owner" = "root" ]; then	
	echo "PASS" >> $RESULT_FILE 2>&1
else
	echo "FAIL" >> $RESULT_FILE 2>&1
fi


echo "[ U-69 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-69 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-70
##############################################
echo "[ U-70 ] : CHECK"
echo "==========[ U-70 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

if [ "`ps -ef | grep sendmail | grep -v grep`" != "" ]; then
        get_noexpn=`cat /etc/mail/sendmail.cf | grep -i "noexpn" | grep -v grep`
	get_novrfy=`cat /etc/mail/sendmail.cf | grep -i "novrfy" | grep -v grep`
	get_goaway=`cat /etc/mail/sendmail.cf | grep -i "goaway" | grep -v grep`
        if [ "$get_noexpn" = ""  || "$get_novrfy" = "" || "$get_goaway" = "" ]; then
                echo "PrivacyOPtions : 'noexpn' or 'novrfy' or 'goaway'"
		echo "PASS" >> $RESULT_FILE 2>&1
        else
		echo "Need to add 'noexpn' or 'novrfy' or 'goaway'" >> $RESULT_FILE 2>&1
		echo "FAIL" >> $RESULT_FILE 2>&1
	fi
else
        echo "sendmail not used" >> $RESULT_FILE 2>&1
	echo "PASS" >> $RESULT_FILE 2>&1
fi

echo "[ U-70 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-70 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-71
##############################################
echo "[ U-71 ] : CHECK"
echo "==========[ U-71 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

get_servertokens=`cat /usr/local/apache2/conf/httpd.conf | grep -i servertokens`
get_serversignature=`cat /usr/local/apache2/conf/httpd.conf | grep -i serversignature`

if [ "$get_servertokens" = "" ] || [ "$get_serversignature" = "" ]; then
	echo "`cat /usr/local/apache2/conf/httpd.conf | grep -v ^[[:space:]]*$ | grep -v '#'`" >> $RESULT_FILE 2>&1
	echo "'ServerTokens Prod' Options or 'ServerSignature Off' Optinos doesn't exist" >> $RESULT_FILE 2>&1
	echo "FAIL" >> $RESULT_FILE 2>&1
else
	echo "'ServerTokens Prod' Options and 'ServerSignature Off' Optinos exist" >> $RESULT_FILE 2>&1
	echo "PASS" >> $RESULT_FILE 2>&1
fi

echo "[ U-71 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-71 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

##############################################
# -  u-72
##############################################
echo "[ U-72 ] : CHECK"
echo "==========[ U-72 START ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1

get_rsy=`cat /etc/rsyslog.conf | grep -v '#' | grep -v ^[[:space:]]*$`
get_info=`cat /etc/rsyslog.conf | grep -v '#' | grep -v ^[[:space:]]*$ | grep *.info`
get_authpriv=`cat /etc/rsyslog.conf | grep -v '#' | grep -v ^[[:space:]]*$ | grep authpriv.*`
get_mail=`cat /etc/rsyslog.conf | grep -v '#' | grep -v ^[[:space:]]*$ | grep mail.*`
get_cron=`cat /etc/rsyslog.conf | grep -v '#' | grep -v ^[[:space:]]*$ | grep cron.*`
get_alert=`cat /etc/rsyslog.conf | grep -v '#' | grep -v ^[[:space:]]*$ | grep *.alert`
get_emerg=`cat /etc/rsyslog.conf | grep -v '#' | grep -v ^[[:space:]]*$ | grep *.emerg`

if [ "$get_info" = "" ] || [ "$get_authpriv" = "" ] || [ "$get_mail" = "" ] || [ "$get_cron" = "" ] || [ "$get_alert" = "" ] || [ "$get_emerg" = "" ]; then
	echo "$get_rsy" >> $RESULT_FILE 2>&1
	echo "" >> $RESULT_FILE 2>&1
	echo "Need to add new entry to /etc/rsyslog.conf" >> $RESULT_FILE 2>&1
	echo "FAIL" >> $RESULT_FILE 2>&1
else
	echo "PASS" >> $RESULT_FILE 2>&1
fi	


echo "[ U-72 ] : END"
echo "" >> $RESULT_FILE 2>&1
echo "==========[ U-72 END   ]" >> $RESULT_FILE 2>&1
echo "" >> $RESULT_FILE 2>&1