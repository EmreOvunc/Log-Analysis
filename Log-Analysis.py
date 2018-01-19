#!/usr/bin/python3
# EmreOvunc info@emreovunc.com

import os

# General Paths & Variables
webIP       = 'YOUR SERVER IP ADDRESS(IPV4)'
logPath     = '/var/log/'
tmpIptables = '/tmp/tmp_iptables.txt'

# Auth Statics
auth        = 'auth'
logAuth     = logPath + 'auth.log'
tmpAuth     = '/tmp/tmp_authList.txt'
grepAuth    = " grep 'sshd.*fail' | grep -ho 'rhost=\w*.\w*.\w*.\w*'"
cutAuth     = " cut -c 7-"
blacklist_Auth = 'blacklist_Auth.txt'

# Apache Statics
apache      = 'apache'
apachePath  = logPath + 'apache2/'
accessLog   = apachePath + 'access.log'
blacklist_Apache = 'blacklist_Apache.txt'
grepApache1 = "grep -E 'scan|script|prompt|bash|admin|root|command|manager|login|sql|db|database|myadmin|mysql" \
              "|administrator|pma|PMA|setup|=+UNION+ALL+select+NULL+--+|AND+1%3D2+--+|OR+1%3D1+--+|response.write%28100%2C000*100%2C000%29" \
              "|%27%3Bprint%28chr%28122%29.chr%2897%29|cat+%2Fetc%2Fpasswd%26'"
grepApache2 = " grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'"
tmpApache   = "/tmp/tmp_apacheList.txt"

# FTP Statics
ftp           = 'vsftpd'
ftpPath       = logPath + ftp + '.log'
tmpFtp        = '/tmp/tmp_ftpList.txt'
grepFtp       = " grep 'FAIL LOGIN' | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'"
blacklist_Ftp = 'blacklist_Ftp.txt'

# Mail Statics
apache_header   = 'Virtual Server WEB Attacks'
auth_header     = 'Virtual Server SSH Attempts'
ftp_header      = 'Virtual Server FTP Attacks'
receiver_mail   = " " + "YOUR MAIL ADDRESS"


def create_black_lists():
    if os.path.exists(tmpApache):
        os.system('rm -rf ' + tmpApache)
    if os.path.exists(tmpAuth):
        os.system('rm -rf ' + tmpAuth)
    if os.path.exists(tmpFtp):
        os.system('rm -rf ' + tmpFtp)
    if not os.path.exists(blacklist_Apache):
        os.system('touch ' + blacklist_Apache)
    if not os.path.exists(blacklist_Auth):
        os.system('touch ' + blacklist_Auth)
    if not os.path.exists(blacklist_Ftp):
        os.system('touch ' + blacklist_Ftp)


def add_iptables(IP):
    if "\n" in IP:
        IP = IP.strip()
    command = 'iptables -A INPUT -s ' + str(IP) + ' -j DROP'
    os.system(command)


def add_black_lists(typeLog, IP):
    if typeLog == auth:
        auth_blacklist = open(blacklist_Auth, 'a')
        auth_blacklist.write("\n"+str(IP))
        auth_blacklist.close()

    elif typeLog == apache:
        apache_blacklist = open(blacklist_Apache, 'a')
        apache_blacklist.write("\n"+str(IP))
        apache_blacklist.close()

    elif typeLog == ftp:
        ftp_blacklist = open(blacklist_Ftp, 'a')
        ftp_blacklist.write("\n"+str(IP))
        ftp_blacklist.close()


def send_mail(typeLog, IP, count):
    if typeLog == auth:
        mail_data = " | mail -s '" + auth_header + "' " + receiver_mail
        content = "echo 'Someone is trying brute-force ! [" + IP + "] tried " + str(count) + " times and BLOCKED :)'"
        mail_fail = str(content + mail_data)
        os.system(mail_fail)

    elif typeLog == apache:
        mail_data = " | mail -s '" + apache_header + "' " + receiver_mail
        content = "echo 'Someone is trying web attacks ! [" + IP + "] tried and BLOCKED :)'"
        mail_fail = str(content + mail_data)
        os.system(mail_fail)

    elif typeLog == ftp:
        mail_data = " | mail -s '" + ftp_header + "' " + receiver_mail
        content = "echo 'Someone is trying ftp attacks ! [" + IP + "] tried and BLOCKED :)'"
        mail_fail = str(content + mail_data)
        os.system(mail_fail)


def eliminate_duplicates(typeLog, file_name):
    wordcount = {}
    for word in file_name.read().split():
        if word not in wordcount:
            wordcount[word] = 1
        else:
            wordcount[word] += 1

    if typeLog == auth:
        for k, v in wordcount.items():
            if v >= 5:
                if not check_same_ip(auth, str(k)):
                    add_black_lists(auth, str(k))
                    add_iptables(str(k))
                    send_mail(auth, str(k), v)

    elif typeLog == apache:
        for k, v in wordcount.items():
            if str(k) != webIP:
                if not check_same_ip(apache, str(k)):
                    add_black_lists(apache, str(k))
                    add_iptables(str(k))
                    send_mail(apache, str(k), 0)

    elif typeLog == ftp:
        for k, v in wordcount.items():
            if str(k) != webIP:
                if not check_same_ip(ftp, str(k)):
                    add_black_lists(ftp, str(k))
                    add_iptables(str(k))
                    send_mail(ftp, str(k), 0)


def check_same_ip(typeLog, IP):
    if typeLog == auth:
        auth_blacklist = open(blacklist_Auth, 'r+')
        for IPs in auth_blacklist:
            if IP in IPs:
                return True
        auth_blacklist.close()
        return False

    elif typeLog == apache:
        apache_blacklist = open(blacklist_Apache, 'r+')
        for IPs in apache_blacklist:
            if IP in IPs:
                return True
        apache_blacklist.close()
        return False

    elif typeLog == ftp:
        ftp_blacklist = open(blacklist_Ftp, 'r+')
        for IPs in ftp_blacklist:
            if IP in IPs:
                return True
        ftp_blacklist.close()
        return False


def apache_log():
    os.system("cat " + accessLog + "|" + grepApache1 + "|" + grepApache2 + " > " + tmpApache)
    tmpApache_File = open(tmpApache, 'r+')
    eliminate_duplicates(apache, tmpApache_File)
    tmpApache_File.close()


def auth_log():
    os.system("cat " + logAuth + "|" + grepAuth + "|" + cutAuth + " > " + tmpAuth)
    tmpAuth_File = open(tmpAuth, 'r+')
    eliminate_duplicates(auth, tmpAuth_File)
    tmpAuth_File.close()


def vsftp_log():
    os.system("cat " + ftpPath + "|" + grepFtp + " > " + tmpFtp)
    tmpFtp_File = open(tmpFtp, 'r+')
    eliminate_duplicates(ftp, tmpFtp_File)
    tmpFtp_File.close()


def main():
    create_black_lists()

    try:
        auth_log()
    except:
        pass

    try:
        apache_log()
    except:
        pass

    try:
        vsftp_log()
    except:
        pass

    os.system('iptables-save')


if __name__ == "__main__":
    main()
