package water.network;

import water.H2O;

import java.io.IOException;
import java.nio.channels.ByteChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

/**
 * Creates either a raw or an SSL/TLS wrapped socket depending on
 * the node's configuration. All sockets used in the application should be
 * created using this class.
 */
public class SocketChannelFactory {

    private SSLSocketChannelFactory sslSocketChannelFactory = null;

    private SocketChannelFactory() throws KeyManagementException,
            NoSuchAlgorithmException,
            UnrecoverableKeyException,
            CertificateException,
            KeyStoreException,
            IOException {
        if(H2O.ARGS.h2o_ssl_enabled) {
            sslSocketChannelFactory = new SSLSocketChannelFactory();
        }
    }

    private ByteChannel channel(SocketChannel sc, boolean client) throws ChannelWrapException {
        if(H2O.ARGS.h2o_ssl_enabled) {
            return sslSocketChannelFactory.wrapChannel(sc, client);
        } else {
            return sc;
        }
    }

    public ByteChannel serverChannel(SocketChannel sc) throws ChannelWrapException {
        return channel(sc, false);
    }

    public ByteChannel clieantChannel(SocketChannel sc) throws ChannelWrapException {
        return channel(sc, true);
    }

}
