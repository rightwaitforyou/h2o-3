package water.network;

import water.H2O;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.channels.ByteChannel;
import java.nio.channels.SocketChannel;
import java.security.*;
import java.security.cert.CertificateException;

public class SSLSocketChannelFactory {

    private SSLContext sslContext = null;

    public SSLSocketChannelFactory() throws
            NoSuchAlgorithmException,
            KeyManagementException,
            UnrecoverableKeyException,
            CertificateException,
            KeyStoreException,
            IOException {
        this.sslContext = SSLContext.getDefault();
        this.sslContext.init(keyManager(), trustManager(), null);
    }

    private TrustManager[] trustManager() throws
            KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore ksTrust = KeyStore.getInstance("JKS");
        ksTrust.load(
                new FileInputStream(H2O.ARGS.h2o_ssl_trustStore),
                H2O.ARGS.h2o_ssl_trustStorePassword.toCharArray()
        );
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(ksTrust);
        return tmf.getTrustManagers();
    }

    private KeyManager[] keyManager() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore ksKeys = KeyStore.getInstance("JKS");
        ksKeys.load(new FileInputStream(H2O.ARGS.h2o_ssl_keyStore),
                H2O.ARGS.h2o_ssl_keyStorePassword.toCharArray()
        );
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ksKeys, H2O.ARGS.h2o_ssl_keyStorePassword.toCharArray());
        return kmf.getKeyManagers();
    }

    public SSLSocketChannelFactory(
            KeyManager[] keyManagers,
            TrustManager[] trustManagers) throws NoSuchAlgorithmException, KeyManagementException {
        this.sslContext = SSLContext.getDefault();
        this.sslContext.init(keyManagers, trustManagers, null);
    }

    public ByteChannel wrapChannel(SocketChannel sc, boolean clientMode) throws ChannelWrapException {
        SSLEngine sslEngine = sslContext.createSSLEngine();
        sslEngine.setUseClientMode(clientMode);
        try {
            return new SSLSocketChannel(sc, sslEngine);
        } catch (IOException e) {
            // TODO log
            throw new ChannelWrapException("Failed to wrap socket channel.", e);
        }
    }

}
