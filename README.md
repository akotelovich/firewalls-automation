Usage
```
rules_to_csv.py --host <hostname> [--vdom <vdom name>] --user <username> --passwd <password> | --ask-password | --passwd-env <ENV-VAR>
```
Output Fortigate rules into CSV file in this format:
```
id;name;uuid;srcaddr;dstaddr;action;status;service;comments;
16;'';3e9763a8-1111-2222-3333-1f6e56830616;"all";"10.99.99.99_32";deny;enable;"ALL";"Comment1";
33;'';43c7c01a-1111-2222-3333-e8541bebdf6b;"Host1_10.9.77.20" "Host2_10.1.78.20";"All_RFC1918";accept;enable;"ALL";"Comment2 (2024-08-27)";
62;"Rule_allow_ALL";9b2f01ea-1111-2222-3333-d8a8e62451f7;"Host3" "Host5";"n-10.10.0.0_16" "n-10.11.0.0_16";accept;enable;"RDP" "SMB" "SSH" "TCP-135";'';
```
