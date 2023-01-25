import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.challenge.Challenge;
import org.shredzone.acme4j.challenge.TlsAlpn01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.CertificateUtils;
import org.shredzone.acme4j.util.KeyPairUtils;

import javax.net.ssl.*;
import javax.swing.*;
import java.io.*;
import java.net.URI;
import java.security.*;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import java.util.Arrays;
import java.util.Collection;

public class Jale {
    // File name of the User Key Pair
    private static final File USER_KEY_FILE = new File("user.key");

    // File name of the Domain Key Pair
    private static final File DOMAIN_KEY_FILE = new File("domain.key");

    // RSA key size of generated key pairs
    private static final int KEY_SIZE = 2048;

    // Create a session for Let's Encrypt.
    // Use "acme://letsencrypt.org" for production server
    String acmeServerUrl = "acme://letsencrypt.org/staging";

    /**
     * Loads a user key pair from {@link #USER_KEY_FILE}. If the file does not exist, a
     * new key pair is generated and saved.
     * <p>
     * Keep this key pair in a safe place! In a production environment, you will not be
     * able to access your account again if you should lose the key pair.
     *
     * @return User's {@link KeyPair}.
     */
    private KeyPair loadOrCreateUserKeyPair() throws IOException {
        if (USER_KEY_FILE.exists()) {
            // If there is a key file, read it
            try (FileReader fr = new FileReader(USER_KEY_FILE)) {
                return KeyPairUtils.readKeyPair(fr);
            }

        } else {
            // If there is none, create a new key pair and save it
            KeyPair userKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
            try (FileWriter fw = new FileWriter(USER_KEY_FILE)) {
                KeyPairUtils.writeKeyPair(userKeyPair, fw);
            }
            return userKeyPair;
        }
    }

    /**
     * Loads a domain key pair from {@link #DOMAIN_KEY_FILE}. If the file does not exist,
     * a new key pair is generated and saved.
     *
     * @return Domain {@link KeyPair}.
     */
    private KeyPair loadOrCreateDomainKeyPair() throws IOException {
        if (DOMAIN_KEY_FILE.exists()) {
            try (FileReader fr = new FileReader(DOMAIN_KEY_FILE)) {
                return KeyPairUtils.readKeyPair(fr);
            }
        } else {
            KeyPair domainKeyPair = KeyPairUtils.createKeyPair(KEY_SIZE);
            try (FileWriter fw = new FileWriter(DOMAIN_KEY_FILE)) {
                KeyPairUtils.writeKeyPair(domainKeyPair, fw);
            }
            return domainKeyPair;
        }
    }


    /**
     * Finds your {@link Account} at the ACME server. It will be found by your user's
     * public key. If your key is not known to the server yet, a new account will be
     * created.
     * <p>
     * This is a simple way of finding your {@link Account}. A better way is to get the
     * URL of your new account with {@link Account#getLocation()} and store it somewhere.
     * If you need to get access to your account later, reconnect to it via  by using the stored location.
     *
     * @param session
     *         {@link Session} to bind with
     * @return {@link Account}
     */
    private Account findOrRegisterAccount(Session session, KeyPair accountKey) throws AcmeException {
        // Ask the user to accept the TOS, if server provides us with a link.
        URI tos = session.getMetadata().getTermsOfService();
        if (tos != null) {
            acceptAgreement(tos);
        }

        Account account = new AccountBuilder()
                .agreeToTermsOfService()
                .useKeyPair(accountKey)
                .create(session);
//        LOG.info("Registered a new user, URL: {}", account.getLocation());

        return account;
    }

    /**
     * Presents the user a link to the Terms of Service, and asks for confirmation. If the
     * user denies confirmation, an exception is thrown.
     *
     * @param agreement
     *         {@link URI} of the Terms of Service
     */
    public void acceptAgreement(URI agreement) throws AcmeException {
        int option = JOptionPane.showConfirmDialog(null,
                "Do you accept the Terms of Service?\n\n" + agreement,
                "Accept ToS",
                JOptionPane.YES_NO_OPTION);
        if (option == JOptionPane.NO_OPTION) {
            throw new AcmeException("User did not accept Terms of Service");
        }
    }

    //start a thread for simple provisional ssl server
    public void startSSLServer(KeyPair serverKeyPair, X509Certificate serverCertificate) throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException, IOException, CertificateException, UnrecoverableKeyException {
        //sample code from http://www.java2s.com/example/java-api/javax/net/ssl/sslserversocket/accept-0-0.html

        KeyStore ks = KeyStore.getInstance("PKCS12");
        FileInputStream inputStream = new FileInputStream("D:\\work\\Jale\\challengeCert.pfx");
        ks.load(inputStream, "changeit".toCharArray());
        inputStream.close();
/*
        // create the KeyStore and load the JKS file
        KeyStore ks = KeyStore.getInstance("JKS");
        X509Certificate[] chain = new X509Certificate[] { serverCertificate };

        String alias1 = serverCertificate.getSubjectX500Principal().getName();
        ks.setCertificateEntry(alias1, serverCertificate);

// store the private key
        ks.setKeyEntry("nanoart", serverKeyPair.getPrivate(), "changeit".toCharArray(), chain );
*/

// may take a look of https://docs.oracle.com/javase/10/security/sample-code-illustrating-secure-socket-connection-client-and-server.htm#JSSEC-GUID-3561ED02-174C-4E65-8BB1-5995E9B7282C
        // initialize key and trust manager factory
//        final KeyManagerFactory keyManagerFactory =  KeyManagerFactory.getInstance( KeyManagerFactory.getDefaultAlgorithm() );
//        keyManagerFactory.init( ks, "changeit".toCharArray() );

        // https://stackoverflow.com/questions/15076820/java-sslhandshakeexception-no-cipher-suites-in-common
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory
                .getDefaultAlgorithm());
        kmf.init(ks, "changeit".toCharArray());



        final TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance( TrustManagerFactory.getDefaultAlgorithm() );
        trustManagerFactory.init( ks );

        // initialize the SSL context
        final SSLContext sslContext = SSLContext.getInstance( "TLS" );
        // sslContext.init( keyManagerFactory.getKeyManagers(),
        //      trustManagerFactory.getTrustManagers(), new SecureRandom() );
        sslContext.init( kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), null );




        final SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

        final int serverPort = 8443;
        final SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory
                .createServerSocket(serverPort);

//        sslServerSocket.setNeedClientAuth(true);
        sslServerSocket.setEnabledProtocols(new String[]{"TLSv1.2"});
/*
        final TestRunnable testRunnable = new TestRunnable(serverPort);
        final Thread thread = new Thread(testRunnable);
        thread.start();
 */

        // NIO to be implemented
        while (true) {
            SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
            // Get an SSLParameters object from the SSLSocket
            SSLParameters sslp = sslSocket.getSSLParameters();

            // Populate SSLParameters with the ALPN values
            // As this is server side, put them in order of preference
//        String[] serverAPs ={ "h2", "http/1.1", "tls-alpn-01" };
            String[] serverAPs ={ "acme-tls/1" };
            sslp.setApplicationProtocols(serverAPs);

            // If necessary at any time, get the ALPN values set on the
            // SSLParameters object with:
            // String serverAPs = sslp.setApplicationProtocols();

            // Populate the SSLSocket object with the ALPN values
            sslSocket.setSSLParameters(sslp);

            sslSocket.startHandshake();

            // After the handshake, get the application protocol that
            // has been negotiated

            String ap = sslSocket.getApplicationProtocol();
            System.out.println("Application Protocol server side: \"" + ap + "\"");

            // Continue with the work of the server
            sslSocket.close();
        }




        /*
        InputStream sslIS = sslSocket.getInputStream();
        OutputStream sslOS = sslSocket.getOutputStream();
        sslIS.read();
        sslOS.write(85);
        sslOS.flush();
        sslSocket.close();

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

         */
    }

    private Challenge tlsAlpnChallenge(Authorization auth) throws IOException {
        String domainName = auth.getIdentifier().getDomain();
        TlsAlpn01Challenge challenge = auth.findChallenge(TlsAlpn01Challenge.class);

        Identifier identifier = auth.getIdentifier();
        byte[] acmeValidation = challenge.getAcmeValidation();
        KeyPair certKeyPair = KeyPairUtils.createKeyPair(2048);
        X509Certificate cert = CertificateUtils.
                createTlsAlpn01Certificate(certKeyPair, identifier, acmeValidation);

        return challenge;
    }


    /**
     * Generates a certificate for the given domains. Also takes care for the registration
     * process.
     *
     * @param domains
     *         Domains to get a common certificate for
     */
    public void fetchCertificate(Collection<String> domains, String password, String email) throws AcmeException, IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {
        // Load the user key file. If there is no key file, create a new one.
        KeyPair userKeyPair = loadOrCreateUserKeyPair();
        System.out.println("Success load the user's key pair.");

        // Create a session for Let's Encrypt.
        Session session = new Session(acmeServerUrl);

        // Get the Account.
        // If there is no account yet, create a new one.
        Account acct = findOrRegisterAccount(session, userKeyPair); // email
//        LOG.debug("Success get the let's encrypt account.");

        // Load or create a key pair for the domains. This should not be the userKeyPair!
        KeyPair domainKeyPair = loadOrCreateDomainKeyPair();
//        LOG.debug("Success load domain's key pair.");

        // Order the certificate
        //* Short-Term Automatic Renewal based certificates cannot be revoked.
//        if(session.getMetadata().isAutoRenewalEnabled()){
//            order = acct.newOrder()
//                    .domains(domains)
//                    .autoRenewal()
//                    .create();
//        } else {
        Order order = acct.newOrder().domains(domains).create();
//        }

        // Perform all required authorizations
        for (Authorization auth : order.getAuthorizations()) {
            authorize(auth);
        }
/*
        // Generate a CSR for all of the domains, and sign it with the domain key pair.
        CSRBuilder csrb = new CSRBuilder();
        csrb.addDomains(domains);
        csrb.sign(domainKeyPair);

        // Write the CSR to a file, for later use.
        try (Writer out = new FileWriter(DOMAIN_CSR_FILE)) {
            csrb.write(out);
        }

        // Order the certificate
        order.execute(csrb.getEncoded());
*/
        // Wait for the order to complete
        try {
            int attempts = 10;
            while (order.getStatus() != Status.VALID && attempts-- > 0) {
//                LOG.info("Current order status: {}, attempts: {}", order.getStatus(), attempts);
                if (order.getStatus() == Status.INVALID) {
//                    LOG.error("Order has failed, reason: {}", order.getError());
//                    throw new AcmeException("Order failed... Giving up.");
                }

                // Wait for a few seconds
                Thread.sleep(3000L);

                // Then update the status
                order.update();
            }
        } catch (InterruptedException ex) {
//            LOG.error("interrupted", ex);
            Thread.currentThread().interrupt();
        }

        // Get the certificate
        org.shredzone.acme4j.Certificate certificate = order.getCertificate();

        System.out.println("Success! The certificate for domains has been generated!");


/*
        LOG.info("Certificate URL: {}", certificate.getLocation());

        // Write a combined file containing the certificate and chain.
        try (FileWriter fw = new FileWriter(DOMAIN_CHAIN_FILE)) {
            certificate.writeCertificate(fw);
        }
        byte[] pfxBytes;
        java.security.cert.Certificate[] certs = certificate.getCertificateChain().stream().toArray(java.security.cert.Certificate[]::new);
        try {
            pfxBytes = getPfxBytes(certs, domainKeyPair, password);
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            LOG.error("Parse certificate to bytes failed: ", e);
            throw e;
        }
        return pfxBytes;

 */
    }

    private void authorize(Authorization auth) throws AcmeException, IOException {

        // The authorization is already valid. No need to process a challenge.
        if (auth.getStatus() == Status.VALID) {
            return;
        }

        // Find the desired challenge and prepare it.
        Challenge challenge =  tlsAlpnChallenge(auth);


        // If the challenge is already verified, there's no need to execute it again.
        if (challenge.getStatus() == Status.VALID) {
//            LOG.info("Current challenge status: {}, no need to start challenge.", challenge.getStatus());
            return;
        }

        // Now trigger the challenge.
        challenge.trigger();

        // Poll for the challenge to complete.
        try {
            int attempts = 10;
            while (challenge.getStatus() != Status.VALID && attempts-- > 0) {
//                LOG.info("Current challenge status: {}, attempts left: {}", challenge.getStatus(), attempts);
                if (challenge.getStatus() == Status.INVALID) {
//                    LOG.error("Challenge has failed, reason: {}", challenge.getError());
                    throw new AcmeException("Challenge failed... Giving up.");
                }

                // Wait for a few seconds
                Thread.sleep(3000L);

                // Then update the status
                challenge.update();
            }
        } catch (InterruptedException ex) {
//            LOG.error("interrupted", ex);
            Thread.currentThread().interrupt();
        }

        // All reattempts are used up and there is still no valid authorization?
        if (challenge.getStatus() != Status.VALID) {
            throw new AcmeException("Failed to pass the challenge for domain "
                    + auth.getIdentifier().getDomain() + ", ... Giving up.");
        }

//        LOG.info("Challenge has been completed. Remember to remove the validation resource.");
    }

    public static void main(String[] args) {

        Security.addProvider(new BouncyCastleProvider());


        String[] domainsTest ={ "test.bletchley19.com" };
        Collection<String> domains = Arrays.asList(domainsTest);
        try {
            Jale ct = new Jale();
            ct.startSSLServer(null, null);
//            ct.fetchCertificate(domains, "changeit", "support@bletvhley19.com");
        } catch (Exception ex) {
            System.out.println("Failed to get a certificate for domains " + domains + ex);
        }





    }
}
