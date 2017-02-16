import os

Log_Path = '/var/log/auth.log'
Dsk_Path = '/tmp/'
wordcount = {}
euid = os.geteuid()

# Emre Ovunc
# info@emreovunc.com

def mail_func(k,v):
    receiver_mail = " info@emreovunc.com"
    mail_data= " | mail -s 'Virtual Ubuntu SSH Attempts' " + receiver_mail
    content = "echo 'Someone is trying brute-force ! [" + str(k) + "] tried " + str(v) +" times and BLOCKED :)'"
    ssh_fail = content + mail_data
    os.system(str(ssh_fail))

def main():
    if euid != 0:
        print "[ERROR]You should have root permissions to run this program ! "
    else:
        if os.path.exists(Log_Path):
            if os.path.isdir(Dsk_Path):
                if os.path.exists(Dsk_Path+"SSH_IP_BlackList.txt"):
                    os.system("rm " + Dsk_Path + "SSH_IP_BlackList.txt" )
            else:
                print "[ERROR] Your desktop path is not found !\n Please give your path manually."
        else:
            print "[ERROR] Your 'auth.log' is not found !\n Please give your log file manually."
        os.system("cat " + Log_Path + " | grep 'sshd.*fail' | grep -ho 'rhost=\w*.\w*.\w*.\w*' | cut -c 7- > " + Dsk_Path + "SSH_IP_BlackList.txt")
        file = open( Dsk_Path + "SSH_IP_BlackList.txt", "r+")
        for word in file.read().split():
            if word not in wordcount:
                wordcount[word] = 1
            else:
                wordcount[word] += 1
        for k,v in wordcount.items():
            if (v >= 5):
                duplicate = iptables(str(k))
                if duplicate == False:
                    os.system("iptables -A INPUT -s " + str(k) + " -j DROP")
                    mail_func(k,v)
        os.system("rm -rf " + Dsk_Path + "SSH_IP_BlackList.txt")
        try:
            os.system("iptables-save")
        except:
            pass
        os.system("rm -rf " + Dsk_Path + "iptables.txt")


def iptables(ip):
        dup = False
        os.system("iptables -L > " + Dsk_Path +"iptables.txt")
        ip_file = open( Dsk_Path + "iptables.txt", "r+")
        rule = "DROP       all  --  " + ip
        for line in ip_file:
            if rule in line:
                dup = True
        return dup

if __name__ == "__main__":
    main()
