package fr.arkey.elasticsearch.oauth.tools;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.file.Paths;

/**
 * Establish a SSL connection to a host and port, writes a byte and
 * prints the response. See
 * http://confluence.atlassian.com/display/JIRA/Connecting+to+SSL+services
 */
public class SSLPoke {
    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: " + SSLPoke.class.getName() + " <host> <port>");
            System.exit(1);
        }
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        System.out.println(host + ":" + port);
        my_poke(host, port);
//        original_poke(args[0], Integer.parseInt(args[1]));
    }

    private static void my_poke(String host, int port) {
        try {
//            SSLContext sslContext = SSLContext.getInstance("TLS");
//            KeyStore ks;
//            try(InputStream inputStream = new BufferedInputStream(Files.newInputStream(Paths.get("/Users/brice/work/shield-oauth-plugin/internal-chain-truststore.jks")))) {
//                ks = KeyStore.getInstance("JKS");
//                ks.load(inputStream, "changeit".toCharArray());
//            }
//            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
//                    TrustManagerFactory.getDefaultAlgorithm()
//            );
//            trustManagerFactory.init((KeyStore) null);
//            trustManagerFactory.init(ks);
//
//            sslContext.init(null,
//                            trustManagerFactory.getTrustManagers(),
//                            null);


            SSLContext sslContext = HttpClients.sslContext(null,
                                                           new TrustManager[]{
                                                                   HttpClients.AlternateTrustManager.trustManager(Paths.get("/Users/brice/work/shield-oauth-plugin/internal-chain-truststore.jks"), "changeit"),
                                                                   HttpClients.systemTrustManager(),
                                                                   });

            SSLSocketFactory socketFactory = sslContext.getSocketFactory();
            Socket sslsocket = socketFactory.createSocket(host, port);

            InputStream in = sslsocket.getInputStream();
            OutputStream out = sslsocket.getOutputStream();

            // Write a test byte to get a reaction :)
            out.write(1);

            while (in.available() > 0) {
                System.out.print(in.read());
            }
            System.out.println("Successfully connected");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    private static void original_poke(String host, int port) {
        try {
            SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket sslsocket = (SSLSocket) sslsocketfactory.createSocket(host, port);

            InputStream in = sslsocket.getInputStream();
            OutputStream out = sslsocket.getOutputStream();

            // Write a test byte to get a reaction :)
            out.write(1);

            while (in.available() > 0) {
                System.out.print(in.read());
            }
            System.out.println("Successfully connected");

        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }
}
