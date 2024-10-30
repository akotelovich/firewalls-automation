Get security rules from Fortigate in CSV format
```
fg_rules_to_csv.py --host <hostname> [--vdom <vdom name>] --user <username> --passwd <password> | --ask-password | --passwd-env <ENV-VAR>
```

```
Similar for Checkpoint security rules:
```
cp_rules_to_csv.py --host <hostname> --policy <policy name> --user <username> [--outfile file.csv] --passwd <password> | --ask-password | --passwd-env <ENV-VAR>
```
