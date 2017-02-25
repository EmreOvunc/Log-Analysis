#!/usr/bin/python
import os

Apc_Path = '/var/log/apache2/'
Log_Path = '/var/log/auth.log'
Dsk_Path = '/tmp/'
wordcount = {}
## Web_IP will be your web server external IP address.
# Change it
Web_IP = "8.8.8.8"
tmp_Logs = {}
euid = os.geteuid()

def mail_func(k,v,header,flag):
    receiver_mail = " info@emreovunc.com"
    mail_data = " | mail -s '" + header + "' " + receiver_mail
    if flag == "ssh":
        content = "echo 'Someone is trying brute-force ! [" + str(k) + "] tried " + str(v) +" times and BLOCKED :)'"
    elif flag == "apache":
        content = "echo 'Someone is trying web attacks ! [" + str(k) + "] tried in "+ str(v) +" and BLOCKED :)'"
    else:
        content = "echo 'Bad Message! :('"
    mail_fail = content + mail_data
    os.system(str(mail_fail))

def main():
    if os.path.exists(Log_Path):
        if os.path.isdir(Dsk_Path):
            if os.path.exists(Dsk_Path+"SSH_IP_BlackList.txt"):
                os.system("rm " + Dsk_Path + "SSH_IP_BlackList.txt" )
        else:
            print "[ERROR] Your tmp path is not found !\n Please give your path manually."
    else:
        print "[ERROR] Your 'auth.log' is not found !\n Please give your log file manually."
    os.system("cat " + Log_Path + " | grep 'sshd.*fail' | grep -ho 'rhost=\w*.\w*.\w*.\w*' | cut -c 7- > " + Dsk_Path + "SSH_IP_BlackList.txt")
    file = open( Dsk_Path + "SSH_IP_BlackList.txt", "r+")
    for word in file.read().split():
        if word not in wordcount:
            wordcount[word] = 1
        else:
            wordcount[word] += 1
    header = "Virtual Ubuntu SSH Attempts"
    for k,v in wordcount.items():
        if (v <= 5):
            duplicate = iptables(str(k))
            if duplicate == False:
                os.system("iptables -A INPUT -s " + str(k) + " -j DROP")
                mail_func(k,v,header,"ssh")
    os.system("rm -rf " + Dsk_Path + "SSH_IP_BlackList.txt")
    try:
        os.system("iptables-save")
    except:
        pass
    os.system("rm -rf " + Dsk_Path + "iptables.txt")
    apache2_log()

def apache2_log():
    if os.path.exists(Apc_Path+"access.log"):
        if not os.path.isdir(Dsk_Path):
            print "[ERROR] Your tmp path is not found !\n Please give your path manually."
    else:
        print "[ERROR] Your 'auth.log' is not found !\n Please give your log file manually."
    os.chdir(Apc_Path)
    tmp_cnt = 0
    for file in os.listdir(Apc_Path):
        if file.startswith("access") and file.endswith(".gz"):
            os.system ("gzip -d " + Apc_Path + file)
            if os.path.exists(Dsk_Path+"Apache2_IP_Blacklist.txt"):
                os.system("cat " + Apc_Path + file[:12] + " | grep -E 'scan|script|prompt|bash|admin|root|command|manager|login|sql|db|database|myadmin|mysql|administrator|pma|PMA|setup' | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' >> " + Dsk_Path + "Apache2_IP_Blacklist.txt")
                tmp_Logs[tmp_cnt] = file
            else:
                os.system("cat " + Apc_Path + file[:12] + " | grep -E 'scan|script|prompt|bash|admin|root|command|manager|login|sql|db|database|myadmin|mysql|administrator|pma|PMA|setup' | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' > " + Dsk_Path + "Apache2_IP_Blacklist.txt")
                tmp_Logs[tmp_cnt] = file
            tmp_cnt += 1
    file = open(Dsk_Path + "Apache2_IP_Blacklist.txt", "r+")
    for word in file.read().split():
        if word not in wordcount:
            wordcount[word] = 1
        else:
            wordcount[word] += 1
    header = "Virtual Ubuntu WEB Attacks"
    tmp_cnt = 0
    for k,v in wordcount.items():
        if str(k) != Web_IP:
            duplicate = iptables(str(k))
            if duplicate == False:
                os.system("iptables -A INPUT -s " + str(k) + " -j DROP")
                mail_func(k,tmp_Logs[tmp_cnt],header,"apache")
                tmp_cnt += 1
    os.system("rm -rf " + Dsk_Path + "Apache2_IP_Blacklist.txt")
    try:
        os.system("iptables-save")
    except:
        pass
    os.system("rm -rf " + Dsk_Path + "iptables.txt")
    os.system("gzip /var/log/apache2/access.log.*")
    os.system("gzip -d /var/log/apache2/access.log.1")

def iptables(ip):
    dup = False
    os.system("iptables -S > " + Dsk_Path +"iptables.txt")
    ip_file = open( Dsk_Path + "iptables.txt", "r+")
    rule = "-A INPUT -s " + ip
    for line in ip_file:
        if rule in line:
            dup = True
    return dup

if __name__ == "__main__":
    if euid != 0:
        print "[ERROR]You should have root permissions to run this program ! "
    else:
        main()
