### Jale (Java LesEncrpt demo client)


### ACME server

[acme2certifier](https://github.com/grindsa/acme2certifier)

[boulder](https://github.com/letsencrypt/boulder)

[pebble](https://github.com/letsencrypt/pebble)

[Root certificates generation using ACME server Pebble](https://blog.xoxzo.com/2020/11/18/root-certificates-generation-using-acme-server-pebble/)

### ALPN check
```
openssl s_client -connect  192.168.0.3:8443 -alpn acme-tls/1 -servername test.bletchley19.com -msg -showcerts
```

### License
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)