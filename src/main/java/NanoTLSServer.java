import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class NanoTLSServer implements Runnable {
    private KeyPair serverKeyPair;
    private X509Certificate serverCertificate;
    private boolean running = true;
    SSLSocket sslSocket = null;

    public NanoTLSServer(KeyPair sKP, X509Certificate serCert) {
        serverKeyPair = sKP;
        serverCertificate = serCert;
        // store parameter for later user
    }

    public void stop() {
        running = false;
        //also close the socket
        if(sslSocket != null) {
            try {
                sslSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void run() {
        try {
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
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(ks);

            // initialize the SSL context
            final SSLContext sslContext = SSLContext.getInstance("TLS");
            // sslContext.init( keyManagerFactory.getKeyManagers(),
            //      trustManagerFactory.getTrustManagers(), new SecureRandom() );
            sslContext.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);


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
            //LetsEncrypt will visit this SSL server from multiple IPs
            // NIO to be implemented, https://stackoverflow.com/questions/53323855/sslserversocket-and-certificate-setup
            while (running) {
                sslSocket = (SSLSocket) sslServerSocket.accept();
                // Get an SSLParameters object from the SSLSocket
                SSLParameters sslp = sslSocket.getSSLParameters();

                //todo
                SNIHostName serverName = new SNIHostName("test.bletchley19.com");
                List<SNIServerName> serverNames = new ArrayList<>(1);
                serverNames.add(serverName);
                sslp.setServerNames(serverNames);

                // Populate SSLParameters with the ALPN values
                // As this is server side, put them in order of preference
//        String[] serverAPs ={ "h2", "http/1.1", "tls-alpn-01" };
                String[] serverAPs = {"acme-tls/1"};
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

        }
        catch (Exception ex) {
            System.out.println("Error: " + ex);
        }

    }
}
