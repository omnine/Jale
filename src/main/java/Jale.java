public class Jale {
    //start a thread for simple provisional ssl server
    public static void main(String[] args) {

        private Challenge tlsAlpnChallenge(Authorization auth) throws AcmeException, IOException {
            String domainName = auth.getIdentifier().getDomain();
            TlsAlpn01Challenge challenge = auth.findChallenge(TlsAlpn01Challenge.class);
            if (challenge == null) {
                throw new AcmeException("Found no " + TlsAlpn01Challenge.TYPE + " challenge.");
            }

            Identifier identifier = auth.getIdentifier();
            byte[] acmeValidation = challenge.getAcmeValidation();
            KeyPair certKeyPair = KeyPairUtils.createKeyPair(2048);
            X509Certificate cert = CertificateUtils.
                    createTlsAlpn01Certificate(certKeyPair, identifier, acmeValidation);

            java.security.cert.Certificate[] certs = new java.security.cert.Certificate[]{cert};
            byte[] pfxBytes = new byte[0];
            try {
                pfxBytes = getPfxBytes(certs, certKeyPair, Constant.CERT_PWD);
            } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
                LOG.error("Parse certificate to bytes failed: ", e);
//            throw e;
            }
            String certPath = Constant.DUALSHIELD_CERTS_PATH+"challengeCert.pfx";
            OutputStream outputStream = new FileOutputStream(certPath);
            outputStream.write(pfxBytes);
            outputStream.close();

            MBeanServerManager mBeanServerManager =  new MBeanServerManager();
            try{
                mBeanServerManager.reloadSslForChallenge( certPath, Constant.CERT_PWD, "PKCS12", domainName, "RSA");
            } catch(Exception e) {
                LOG.error("Fail to reload certificate: ${e.toString()}");
            }

            return challenge;
        }


        //sample code from http://www.java2s.com/example/java-api/javax/net/ssl/sslserversocket/accept-0-0.html
        final KeyPair serverKeyPair = generateKeyPair();
        final PrivateKey serverPrivateKey = serverKeyPair.getPrivate();
        final DateTime notBefore = new DateTime();
        final DateTime notAfter = notBefore.plusDays(1);
        final X509Certificate serverCertificate = generateCACertificate(serverKeyPair, "CN=Test", notBefore,
                notAfter);//from w  w w.j a v  a2s  .  c  o  m

        final KeyManager keyManager = new ServerTestX509KeyManager(serverPrivateKey, serverCertificate);
        final TrustManager trustManager = new ServerTestX509TrustManager();
        final SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(new KeyManager[] { keyManager }, new TrustManager[] { trustManager }, new SecureRandom());

        final SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

        final int serverPort = 8443;
        final SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory
                .createServerSocket(serverPort);

        sslServerSocket.setNeedClientAuth(true);

        final TestRunnable testRunnable = new TestRunnable(serverPort);
        final Thread thread = new Thread(testRunnable);
        thread.start();

        SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
        LOG.debug("server accepted");
        InputStream inputStream = sslSocket.getInputStream();
        int result = inputStream.read();
        LOG.debug("result: " + result);
        assertEquals(12, result);
        SSLSession sslSession = sslSocket.getSession();
        sslSession.invalidate();
        sslSocket = (SSLSocket) sslServerSocket.accept();
        inputStream = sslSocket.getInputStream();
        result = inputStream.read();
        LOG.debug("result: " + result);
        assertEquals(34, result);


    }
}
