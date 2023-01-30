### Jale (Java LesEncrpt demo client)

We tried to utilize the existing http server hosted in tomcat connector to answer the `tls-alpn-01` challenge. We tried UpgradeProtocol, but failed to add .
Tomcat has a class, but I didn't figured out how to pass the parameters.

Acme4j has a sample, but it doesn't have the `tls-alpn-01` challenge at that moment. So I decided to write my own.

### How to test

LetsEncrypt server (production and staging server) has a requirement that the certificate applicant need to have a public IP and port 443, which is inconvenient for development.

I found a few servers 

- [acme2certifier](https://github.com/grindsa/acme2certifier)
- [boulder](https://github.com/letsencrypt/boulder)
- [pebble](https://github.com/letsencrypt/pebble)

As a matter of fact, Acme4j recommends using Pebble, so I gave it a go.

git clone it to local disk. also download the binary to the folder (I am lazy to install and configure Go environment)

then simply run this command,

D:\research\pebble>pebble_windows-amd64.exe .\test\config\pebble-config.json

```
Pebble 2023/01/27 10:00:33 Starting Pebble ACME server
Pebble 2023/01/27 10:00:34 Generated new root issuer CN=Pebble Root CA 4ae86a with serial 5ee8fa9cce1525bb and SKI cb7ef156c9b425153665d23c7010c0e83f9c0c38
Pebble 2023/01/27 10:00:34 Generated new intermediate issuer CN=Pebble Intermediate CA 60ca14 with serial 2d5dbef668c97ad9 and SKI 308f06f6ee29f9b78d434edeaa6c2e4bcbc461ed
Pebble 2023/01/27 10:00:34 Generated issuance chain: Pebble Root CA 4ae86a -> Pebble Intermediate CA 60ca14
Pebble 2023/01/27 10:00:34 Using system DNS resolver for ACME challenges
Pebble 2023/01/27 10:00:34 Configured to reject 5% of good nonces
Pebble 2023/01/27 10:00:34 Configured to attempt authz reuse for each identifier 50% of the time
Pebble 2023/01/27 10:00:34 Configured to show 3 orders per page
Pebble 2023/01/27 10:00:34 Management interface listening on: 0.0.0.0:15000
Pebble 2023/01/27 10:00:34 Root CA certificate available at: https://0.0.0.0:15000/roots/0
Pebble 2023/01/27 10:00:34 Listening on: 0.0.0.0:14000
Pebble 2023/01/27 10:00:34 ACME directory available at: https://0.0.0.0:14000/dir
```

Accessing https://localhost:14000/dir in browser will return a json,

```
{
   "keyChange": "https://localhost:14000/rollover-account-key",
   "meta": {
      "externalAccountRequired": false,
      "termsOfService": "data:text/plain,Do%20what%20thou%20wilt"
   },
   "newAccount": "https://localhost:14000/sign-me-up",
   "newNonce": "https://localhost:14000/nonce-plz",
   "newOrder": "https://localhost:14000/order-plz",
   "revokeCert": "https://localhost:14000/revoke-cert"
}
```

If you run Jale now, you will hit Pebble server certificate trust problem.

Pebble mentioned,

> "Since the Pebble test CA isn't part of any default CA trust stores you must add the test/certs/pebble.minica.pem certificate to your client's trusted root configuration to avoid HTTPS errors. Your client should offer a runtime option to specify a list of trusted root CAs."

I get cacarts from my JDK, then use KeyStore

![Img](./assets/images/img-20230129160131.png)
 
-Djavax.net.ssl.trustStore=D:\work\Jale\cacerts -Djavax.net.ssl.trustStorePassword=changeit


### ACME server

[acme2certifier](https://github.com/grindsa/acme2certifier)

[boulder](https://github.com/letsencrypt/boulder)

[pebble](https://github.com/letsencrypt/pebble)



### ALPN check
```
openssl s_client -connect  192.168.0.3:8443 -alpn acme-tls/1 -servername test.bletchley19.com -msg -showcerts
```

### Tips

In order to trust Pebble's server certificate, in IntelliJ configuration, add VM option

`-Djavax.net.ssl.trustStore=D:\work\Jale\cacerts -Djavax.net.ssl.trustStorePassword=changeit`

The cacerts is copied from  `C:\Program Files\Java\jre1.8.0_351\lib\security`,
See the details in https://intellij-support.jetbrains.com/hc/en-us/community/posts/115000080810-Setting-Truststore-

### References

[Root certificates generation using ACME server Pebble](https://blog.xoxzo.com/2020/11/18/root-certificates-generation-using-acme-server-pebble/)

### License
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)