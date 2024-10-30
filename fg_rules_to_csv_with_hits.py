import re
import os
import getpass
from netmiko import fortinet
from netmiko import ConnectHandler
import argparse
import csv
import sys

def convert_str(match_obj):
    if match_obj.group(1) is not None and match_obj.group(2) is not None:
        return match_obj.group(1) + "\"" + re.sub(r"\s+", " ", match_obj.group(2)) +"\""


def parse_fw_policy(t, a):
    """
    :param t: configuration text
    :param a: array of configuration intems to be printed
    :return: aray
    """
    fc=0
    fe=0
    #rn=0
    #fs=";"

    ar = []
    col = []
    # process each line separatelly
    for l in t.split("\n"):

        # enter fw policy block
        if re.search("config firewall policy", l):
            fc=1
            continue

        # start next policy statement processing
        if fc==1 and fe==1 and re.search("next", l):
            fe=0
            ar.append(col)
            col = []
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
                col.append(m.group(1))
                continue

        # block inside edit xxx...next
        for i in a:
            res = re.search(r"set "+ i +"\s+(.+)", l)
            if res:
                col.append(res.group(1))

    return ar


def main():
    parser = argparse.ArgumentParser(prog='rules_to_csv.py',
                                     usage='%(prog)s --host <hostname> [--vdom <vdom name>] --user <username> --passwd <password> | --ask-password | --passwd-env <ENV-VAR>',
                                     description="Retrieve rules from firewall into CSV data")
    parser.add_argument("-d", "--hostname", nargs=1, required=True, help="hostname")
    parser.add_argument("-u", "--username", nargs=1, required=True, help="username")
    parser.add_argument("-f", "--outfile", nargs=1, help="output csv file")
    parser.add_argument("-v", "--vdom", nargs=1, help="Fortigate vdom")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--ask_password", action='store_true', help="ask password")
    group.add_argument("-p", "--password", nargs=1, help="password from command line")
    group.add_argument("-e", "--password_env", nargs=1, help="password from environment variable")

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

    data_to_parse = ["id", "name", "uuid", "srcaddr", "dstaddr", "action", "status", "service", "comments"]
    try:
        net_connect = ConnectHandler(
            device_type = "fortinet",
            host = args.hostname[0],
            username = args.username[0],
            password = dev_passwd,
            fast_cli = False,
            global_delay_factor = 2
            #,session_log="output.txt"
        )

        if (args.vdom[0]):
            o = net_connect.send_command ("config vdom", expect_string=r"#")
            o = net_connect.send_command ("edit {}".format(args.vdom[0]), expect_string=r"\) \#")

        txt_fw_policy = net_connect.send_command("show full-configuration firewall policy", expect_string=r"\) \#")

        #join multiline comments into one line
        txt_fw_policy = re.sub(r"^(set comments )\"([^\"]*)\"$", convert_str, txt_fw_policy, flags=re.M)

        #normalize quotation symbols
        txt_fw_policy = re.sub(r"\"", "'", txt_fw_policy, flags=re.M)

        arr_policies = parse_fw_policy (txt_fw_policy, data_to_parse)

        data_to_parse.append('packets')
        data_to_parse.append('hits')
        data_to_parse.append('first_hit')
        data_to_parse.append('last_hit')

        for i in range(0, len(arr_policies)):
            raw_counters = net_connect.send_command("diagnose firewall iprope show 00100004 " + arr_policies[i][0], expect_string=r"\) \#")
            packets = re.search(r"pkts/bytes=([^\/]+)", raw_counters)
            arr_policies[i].append(packets.group(1))

            hits = re.search(r"hit count:(\d+)\n", raw_counters)
            if (hits):
                arr_policies[i].append(hits.group(1))
            else:
                arr_policies[i].append('0')

            first_last_hit = re.search(r"first:(.+) last:(.+)", raw_counters)
            if (first_last_hit):
                arr_policies[i].append(first_last_hit.group(1))
                arr_policies[i].append(first_last_hit.group(2))
            else:
                arr_policies[i].append('0')
                arr_policies[i].append('0')

            #DEBUG: print(arr_policies[i])
        net_connect.send_command("end \n ",expect_string=r"#",read_timeout=90)

        if (args.outfile):
            with open(args.outfile[0], "w+", newline='') as out_csv:
                csv_wr = csv.writer(out_csv, delimiter=',')
                csv_wr.writerow(data_to_parse)
                csv_wr.writerows(arr_policies)
                print("Saved to {}".format(args.outfile[0]))
        else:
            csv_wr = csv.writer(sys.stdout, delimiter=',')
            csv_wr.writerow(data_to_parse)
            csv_wr.writerows(arr_policies)

    except NetmikoTimeoutException:
        print ("Could not connect to {}".format(args.hostname[0]))
    except NetmikoAuthenticationException:
        print ("User {} login was not successful".format(args.username[0]))
    except PermissionError:
        print ("Could not save the data")
    finally:
        if 'net_connect' in locals():
            net_connect.disconnect()

    return None


if __name__ == "__main__" :
    main()
