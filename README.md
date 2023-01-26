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

### Tips

In order to trust Pebble's server certificate, in IntelliJ configuration, add VM option

`-Djavax.net.ssl.trustStore=D:\work\Jale\cacerts -Djavax.net.ssl.trustStorePassword=changeit`

The cacerts is copied from  `C:\Program Files\Java\jre1.8.0_351\lib\security`,
See the details in https://intellij-support.jetbrains.com/hc/en-us/community/posts/115000080810-Setting-Truststore-

### License
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)