import re
import os
import getpass
from netmiko import fortinet
from netmiko import ConnectHandler
import argparse


def convert_str(match_obj):
    if match_obj.group(1) is not None and match_obj.group(2) is not None:
        return match_obj.group(1) + "\"" + re.sub(r"\s+", " ", match_obj.group(2)) +"\""


def parse_and_print(t, a):
    """
    :param t: configuration text
    :param a: array of configuration intems to be printed
    :return: None
    """
    fc=0
    fe=0
    rn=0
    fs=";"

    #print csv header
    for i in a:
        print(i + fs, end="")

    # process each line separatelly
    for l in t.split("\n"):
        # enter fw policy block
        if re.search("config firewall policy", l):
            fc=1
            continue

        # start next policy statement processing
        if fc==1 and fe==1 and re.search("next", l):
            fe=0
            continue

        # last end statment, stop processing
        if fc==1 and fe==0 and re.search("end", l):
            fe=0
            break

        # enter edit policy block
        if fc==1:
            m = re.search(r"edit\s+(\w+)", l)
            if m:
                fe=1
                rn = m.group(1)
                print("\n"+rn, end=fs)
                continue

        # block inside edit xxx...next
        for i in a:
            res = re.search(r"set "+i+"\s+(.+)", l)
            if res:
                print(res.group(1), end=fs) #all sets
        #
    return None


def main():
    parser = argparse.ArgumentParser(prog='PROG',
                        usage='%(prog)s --host <hostname> [--vdom <vdom name>] --user <username> --passwd <password> | --ask-password | --passwd-env <ENV-VAR>',
                        description="Retrieve rules from firewall")
    parser.add_argument("--hostname", nargs=1, required=True,
                        help="hostname")
    parser.add_argument("--username", nargs=1, required=True,
                        help="username")
    parser.add_argument("--vdom", nargs=1,
                        help="vdom")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ask_password", action='store_true',
                       help="ask password")
    group.add_argument("--password", nargs=1,
                        help="password")
    group.add_argument("--password_env", nargs=1,
                        help="password environment variable")

    args = parser.parse_args()

    dev_passwd = ""
    if (args.ask_password):
        # password from stdin
        dev_passwd = getpass.getpass()
    elif (args.password_env != None):
        # password from enviroment variable
        dev_passwd = os.getenv(format(args.password_env[0]))
    elif (args.password != None):
        # password from command line
        dev_passwd = args.password[0]
    else:
        raise SystemExit(1)

    a = ["name", "uuid", "srcaddr", "dstaddr", "action", "status", "service", "comments"]
    net_connect = ConnectHandler(
        device_type = "fortinet",
        host = args.hostname[0],
        username = args.username[0],
        password = dev_passwd,
        fast_cli = False,
        global_delay_factor = 2
        #,session_log="output.txt"
    )

    output = ""
    if (args.vdom[0]):
        o = net_connect.send_command ("config vdom", expect_string=r"#")
        o = net_connect.send_command ("edit {}".format(args.vdom[0]), expect_string=r"\) \#")

    t = net_connect.send_command("show full-configuration firewall policy", expect_string=r"\) \#")
    net_connect.send_command("end \n ",expect_string=r"#",read_timeout=90)
    net_connect.disconnect()

    #join multiline comments into one line
    t = re.sub(r"^(set comments )\"([^\"]*)\"$", convert_str, t, flags=re.M)
    parse_and_print (t, a)

    #TODO: save to file
    #backup_file = open("backup-config-firewall/" + "-root.txt", "w+")
    #backup_file.write(t)
    #print("Saved to " + fileName + ".txt")
    return None


if __name__ == "__main__" :
    main()
