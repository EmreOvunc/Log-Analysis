#!/usr/bin/python3

##########################
#     Basic SSH Agent    #
##########################
#        14.11.2017      #
##########################
#        Emre OVUNC      #
##########################

from os        import system
from os        import geteuid
from sys       import exit
from socket    import socket
from socket    import AF_INET
from socket    import SOL_SOCKET
from socket    import SOCK_STREAM
from socket    import SO_REUSEADDR
from threading import Thread

if int(geteuid()) != 0:
    print('Please, run it as a ROOT!')
    exit()

bind_ip     = input('Enter SSH Server Interface IP : ')
bind_port   = input('Enter SSH Server Port Number  : ')


class Connection(Thread):
    def __init__(self, conn, ip_address):
        super(Connection, self).__init__()
        self.conn = conn
        self.ip_address = ip_address

    def run(self):
        try:
            data = self.conn.recv(4096)
        except:
            pass

        try:
            system('iptables -A INPUT -s ' + str(self.ip_address) + ' -j DROP')
            system('iptables-save')
        except:
            pass


def listenssh():
    try:
        ssh_server = socket(AF_INET, SOCK_STREAM)
        ssh_server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        ssh_server.bind((bind_ip, int(bind_port)))
        ssh_server.listen(100)
    except:
        pass

    threads    = []

    while True:
        try:
            (conn, (ip_address, port_number)) = ssh_server.accept()
        except:
            pass

        try:
            new_thread = Connection(conn, ip_address)
            new_thread.start()
            threads.append(new_thread)
        except:
            pass

        try:
            if not threads[0].is_alive():
                del threads[0]
        except:
            pass


if __name__ == '__main__':
    listenssh()
