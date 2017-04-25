#!/usr/bin/python3
# EmreOvunc info@emreovunc.com

import os

# General Paths & Variables
webIP = 'YOUR WEB SERVER IP'
logPath = '/var/log/'

# Auth Statics
auth = 'auth'
logAuth = logPath + 'auth.log'
tmpAuth = '/tmp/tmp_authList.txt'
grepAuth = " grep 'sshd.*fail' | grep -ho 'rhost=\w*.\w*.\w*.\w*'"
cutAuth = " cut -c 7-"
blacklist_Auth = 'blacklist_Auth.txt'

# Apache Statics
apache = 'apache'
apachePath = logPath + 'apache2/'
accessLog = apachePath + 'access.log'
blacklist_Apache = 'blacklist_Apache.txt'
grepApache1 = " grep -E 'scan|script|prompt|bash|admin|root|command|manager|login|sql|db|database|myadmin|mysql|administrator|pma|PMA|setup'"
grepApache2 = " grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'"
tmpApache = "/tmp/tmp_apacheList.txt"

# Mail Statics
apache_header = 'Virtual Ubuntu WEB Attacks'
auth_header = 'Virtual Ubuntu SSH Attempts'
receiver_mail = " info@emreovunc.com"

def create_black_lists():
    if not os.path.exists(blacklist_Apache):
        os.system('touch ' + blacklist_Apache)
    if not os.path.exists(blacklist_Auth):
        os.system('touch ' + blacklist_Auth)

def add_iptables(IP):
    os.system('iptables -A INPUT -s ' + IP + " -j DROP")

def add_black_lists(typeLog, IP):
    if typeLog == auth:
        auth_blacklist = open(blacklist_Auth, 'a')
        auth_blacklist.write("\n"+str(IP))
        auth_blacklist.close()

    elif typeLog == apache:
        apache_blacklist = open(blacklist_Apache, 'a')
        apache_blacklist.write("\n"+str(IP))
        apache_blacklist.close()

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

def main():
    create_black_lists()
    auth_log()
    apache_log()
    os.system('iptables-save')

if __name__ == "__main__":
    main()
