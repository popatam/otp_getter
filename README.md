# otp getter

# how to use with tunnelblick
1. make dir example.tblk
```
mkdir -p example.tblk
```

2. copy ovpn configuration file to example.tblk
3. create password-replace.user.sh in example.tblk
```bash
cat <<EOF > example.tblk/password-replace.user.sh
#!usr/bin/env bash

/path/to/otp_getter --service="{service_name}"
EOF
```
4. add otp token to keychain:
```
security add-generic-password -a "{user_name}" -s "{service_name}" -w "{token}"
```
5. open example.tblk in tunnelblick


# links:
* [password-replace.user.sh](https://www.tunnelblick.net/cUsingScripts.html)
* https://www.ietf.org/rfc/rfc6238.html
* https://habr.com/ru/articles/534064/
* https://ss64.com/mac/security.html
