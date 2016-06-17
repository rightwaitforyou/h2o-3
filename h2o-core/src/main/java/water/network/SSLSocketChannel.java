package water.network;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.channels.SocketChannel;

/**
 * This class is based on:
 * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html">Oracle's JSSE guide.</a>
 * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/samples/sslengine/SSLEngineSimpleDemo.java">Oracle's SSLEngine demo.</a>
 *
 * It's a simple wrapper around SocketChannels which enables SSL/TLS
 * communication using {@link javax.net.ssl.SSLEngine}.
 */
public class SSLSocketChannel implements ByteChannel {

    // Buffers holding encrypted data
    private ByteBuffer netInBuffer;
    private ByteBuffer netOutBuffer;

    // Buffers holding decrypted data
    // TODO probably can use only 1 buffer for both with some flag
    private ByteBuffer myAppData;
    private ByteBuffer peerAppData;

    private SocketChannel sc = null;
    private SSLEngine sslEngine = null;

    private boolean closing = false;
    private boolean closed = false;

    public SSLSocketChannel(SocketChannel sc, SSLEngine sslEngine) throws IOException {
        this.sc = sc;
        this.sslEngine = sslEngine;

        sslEngine.setEnableSessionCreation(true);
        SSLSession session = sslEngine.getSession();
        prepareBuffers(session);

        handshake();
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
        if (closing || closed) return -1;

        int read = sc.read(netInBuffer);

        if (read == -1 || read == 0) {
            return read;
        } else {
            return unwrap(dst);
        }
    }

    private synchronized int unwrap(ByteBuffer dst) throws IOException {
        int read = 0;
        SSLEngineResult unwrap;

        do {
            netInBuffer.flip();

            unwrap = sslEngine.unwrap(netInBuffer, dst);
            netInBuffer.compact();

            if (unwrap.getStatus() == SSLEngineResult.Status.OK ||
                    unwrap.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                read += unwrap.bytesProduced();

                if (unwrap.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    tasks();
                }

                if (unwrap.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                    break;
                }
            } else if (unwrap.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                if (read > 0) {
                    break;
                } else {
                    // TODO implement
                }
            } else {
                // Something else went wrong
                throw new IOException("Failed to SSL unwrap with status " + unwrap.getStatus());
            }
        } while(netInBuffer.position() != 0);

        return read;
    }

    @Override
    public int write(ByteBuffer src) throws IOException {
        if(closing || closed) {
            throw new IOException("Cannot perform socket write, the socket is closed (or being closed).");
        }

        if(!flush(netOutBuffer)) {
            return 0;
        }

        return sc.write(wrap(src));
    }

    private synchronized ByteBuffer wrap(ByteBuffer b) throws IOException {
        netOutBuffer.clear();
        SSLEngineResult res = sslEngine.wrap(b, netOutBuffer);

        if (res.getStatus() == SSLEngineResult.Status.OK) {
            if (res.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) tasks();
        } else {
            throw new IOException("Failed to SSL wrap with status " + res.getStatus());
        }

        netOutBuffer.flip();
        return netOutBuffer;
    }

    private boolean flush(ByteBuffer buf) throws IOException {
        int remaining = buf.remaining();
        if ( remaining > 0 ) {
            int written = sc.write(buf);
            return written >= remaining;
        }else {
            return true;
        }
    }

    @Override
    public boolean isOpen() {
        return sc.isOpen();
    }

    @Override
    public void close() throws IOException {
        sslEngine.closeOutbound();
        sslEngine.getSession().invalidate();
        netOutBuffer.clear();
        sc.write(wrap(netOutBuffer));
        sc.close();
    }

    private void prepareBuffers(SSLSession session) {
        int appBufferSize = session.getApplicationBufferSize();
        myAppData = ByteBuffer.allocate(appBufferSize);
        peerAppData = ByteBuffer.allocate(appBufferSize);

        int netBufferSize = session.getPacketBufferSize();

        netInBuffer = ByteBuffer.allocate(netBufferSize);
        netOutBuffer = ByteBuffer.allocate(netBufferSize);
    }

    // -----------------------------------------------------------
    // HANDSHAKE
    // -----------------------------------------------------------

    private SSLEngineResult.HandshakeStatus hs;

    private void handshake() throws IOException {
        sslEngine.beginHandshake();
        hs = sslEngine.getHandshakeStatus();

        SSLEngineResult handshakeResult;

        while(hs != SSLEngineResult.HandshakeStatus.FINISHED &&
                hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
            switch(hs){
                case NEED_WRAP : {
                    try {
                        handshakeResult = handshakeWrap();
                    } catch (SSLException e) {
                        // TODO log
                        handshakeResult = handshakeWrap();
                    }
                    if (handshakeResult.getStatus() == SSLEngineResult.Status.OK) {
                        if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK)
                            hs = tasks();
                    } else if (handshakeResult.getStatus() == SSLEngineResult.Status.CLOSED) {
                        flush(netOutBuffer);
                    } else {
                        throw new IOException("Unexpected status during wrap " + handshakeResult.getStatus());
                    }
                    if ( hs != SSLEngineResult.HandshakeStatus.NEED_UNWRAP || (!flush(netOutBuffer)) ) {
                        // TODO implement
                        return;
                    }
                }
                case NEED_UNWRAP:
                    handshakeResult = handshakeUnwrap();
                    if ( handshakeResult.getStatus() == SSLEngineResult.Status.OK ) {
                        if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                            hs = tasks();
                        }
                    } else if ( handshakeResult.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW ){
                        // TODO implement
                        return;
                    } else if (handshakeResult.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        // TODO implement
                    } else {
                        throw new IOException("Unexpected status during unwrap  " + handshakeResult.getStatus());
                    }
                    break;
                case NEED_TASK :
                    hs = tasks();
                    break;
            }
        }
    }

    private SSLEngineResult handshakeWrap() throws SSLException {
        netOutBuffer.clear();
        SSLEngineResult result = sslEngine.wrap(myAppData, netOutBuffer);
        netOutBuffer.flip();
        hs = result.getHandshakeStatus();
        return result;
    }

    private SSLEngineResult handshakeUnwrap() throws IOException {
        if (netInBuffer.position() == netInBuffer.limit()) {
            netInBuffer.clear();
        }

        SSLEngineResult result;
        boolean cont;
        do {
            netInBuffer.flip();
            result = sslEngine.unwrap(netInBuffer, peerAppData);
            netInBuffer.compact();
            hs = result.getHandshakeStatus();
            if ( result.getStatus() == SSLEngineResult.Status.OK &&
                    result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK ) {
                hs = tasks();
            }

            cont = result.getStatus() == SSLEngineResult.Status.OK &&
                    hs == SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
        } while ( cont );
        return result;
    }

    // -----------------------------------------------------------
    // MISC
    // -----------------------------------------------------------

    private SSLEngineResult.HandshakeStatus tasks() {
        Runnable r;
        while ( (r = sslEngine.getDelegatedTask()) != null) {
            r.run();
        }
        return sslEngine.getHandshakeStatus();
    }
}
