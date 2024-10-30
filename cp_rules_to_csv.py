import json
import csv
import sys
import os
import argparse
import getpass
from cpapi import APIClient, APIClientArgs


def get_name_by_uid(dict, uid):
    fs = " "
    res = ''
    for i in list(uid):
        for j in dict:
            if j.get('uid') == i:
                res = res + j.get('name')
                # append ip address to the hostname
                #if j.get('type') == 'host':
                #    res = res + '_' + j.get('ipv4-address')
                res = res + fs

    res = res[:-1] #remove last character
    return res


def main():
    parser = argparse.ArgumentParser(prog='cp_rules_to_csv.py',
                                     usage='%(prog)s --host <hostname> --policy <policy name> --user <username> [--outfile file.csv] --passwd <password> | --ask-password | --passwd-env <ENV-VAR>',
                                     description="Retrieve rules from firewall into CSV data")
    parser.add_argument("-d", "--hostname", nargs=1, required=True, help="hostname")
    parser.add_argument("-u", "--username", nargs=1, required=True, help="username")
    parser.add_argument("-f", "--outfile", nargs=1, help="output csv file")
    parser.add_argument("-c", "--policy", nargs=1, help="FW policy name")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-a", "--ask_password", action='store_true', help="ask password")
    group.add_argument("-p", "--password", nargs=1, help="password from command line")
    group.add_argument("-e", "--password_env", nargs=1, help="password from environment variable")

    args = parser.parse_args()

    dev_passwd = ''
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

    client_args = APIClientArgs(server=args.hostname[0], unsafe=True)
    
    with APIClient(client_args) as client:
        login_res = client.login(args.username[0], dev_passwd)
        #DEB: client.debug_file = "req.json"

        if login_res.success is False:
            print("Login failed: {}".format(login_res.error_message))
            exit(1)

        p = {}
        p.update({"name":args.policy[0],"limit": "10000", "offset": "0", "details-level": "standard", "show-hits": "true"})
        #TODO: ajust limit
        jf = client.api_query("show-access-rulebase", payload=p)

        data_to_parse = ['num', 'uid', 'name', 'enabled', 'src-neg', 'src', 'dst-neg', 'dst', 'svc-neg', 'svc', 'action', 'hits', 'last-hit', 'comments']
        if (args.outfile):
            out_csv = open(args.outfile[0], "w+", newline='')
            csv_wr = csv.writer(out_csv, delimiter=',')
        else:
            csv_wr = csv.writer(sys.stdout, delimiter=',')

        if jf.success:
            csv_wr.writerow(data_to_parse)
            for i in jf.data['rulebase']:
                for j in i['rulebase']:
                    arr_policy = []
                    if j['rule-number']:
                        arr_policy.append (j['rule-number'])
                        arr_policy.append (j['uid'])
                        if 'name' in j:
                            arr_policy.append ("%r"%j['name']) #append raw string
                        else:
                            arr_policy.append ('')
                        arr_policy.append (j['enabled'])
                        arr_policy.append (str(j['source-negate']))
                        arr_policy.append (get_name_by_uid(jf.data['objects-dictionary'], j['source']))
                        arr_policy.append (str(j['destination-negate']))
                        arr_policy.append (get_name_by_uid(jf.data['objects-dictionary'], j['destination']))
                        arr_policy.append (str(j['service-negate']))
                        arr_policy.append (get_name_by_uid(jf.data['objects-dictionary'], j['service']))
                        arr_policy.append (get_name_by_uid(jf.data['objects-dictionary'], j['action'].split())) # convert str to list
                        arr_policy.append (j['hits']['value'])
                        lh = ''
                        for k in j['hits']:
                            if k =='last-date':
                                lh = j['hits'].get('last-date').get('iso-8601')
                        arr_policy.append(lh)
                        if j['comments'] != "":
                            arr_policy.append ("%r"%j['comments']) #append raw string
                        else:
                            arr_policy.append('')

                        csv_wr.writerow(arr_policy)

            if (args.outfile):
                out_csv.close()
        else:
            print(jf.error_message)

    return None


if __name__ == "__main__" :
    main()
