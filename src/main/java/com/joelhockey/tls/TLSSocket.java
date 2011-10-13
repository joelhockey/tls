/*
 * Copyright 2001-2011 Joel Hockey (joel.hockey@gmail.com).  All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package com.joelhockey.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Provides a TLS Client Socket connection.  Supports
 * TLS_RSA_WITH_RC4_128_MD5, TLS_RSA_WITH_3DES_EDE_CBC_SHA,
 * and TLS_RSA_WITH_AES_128_CBC_SHA without client authentication.
 *
 *	@author		Joel Hockey
 */
public class TLSSocket extends java.net.Socket {

    // Class variables
    public static final byte[] PROTOCOL_VERSION = {0x03, 0x01};
    public static final byte[] COMPRESSION_METHOD = {0x01, 0x00};
    public static final int TLS_RSA_WITH_RC4_128_MD5 = 0x04;
    public static final int TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x0A;
    public static final int TLS_RSA_WITH_AES_128_CBC_SHA = 0x2F;
    // cipher suites supported
    public static final byte[] CIPHER_SUITE = {0x00, 0x06, 0x00, 0x04, 0x00, 0x0a, 0x00, 0x2f};
//    public static final byte[] CIPHER_SUITE = {0x00, 0x02, 0x00, 0x04}; // rc4
//    public static final byte[] CIPHER_SUITE = {0x00, 0x02, 0x00, 0x0a}; // des3
//    public static final byte[] CIPHER_SUITE = {0x00, 0x02, 0x00, 0x2f}; // aes

    public static final int KEY_BLOCK_LENGTH = 104;

    // Instance variables.
    private String host;
    private int port;
    private String proxyHost;
    private int proxyPort;
    private boolean m_useProxy;
    private Record record;
    private Handshake handshake;
    private boolean connected = false;
    private TLSInputStream tlsInputStream;
    private TLSOutputStream tlsOutputStream;

    /**
     * Class constructor.
     *
     * @param   host    The server to connect to.
     * @param   port    The port on the server to connect to.
     * @throws TLSException if it cannot establish a connection.
     */
    public TLSSocket(String host, int port) throws IOException {
        this.host = host;
        this.port = port;
        m_useProxy = false;

        // get the TLS objects
        record = new Record(this);
        handshake = new Handshake(this);
        tlsInputStream = new TLSInputStream(this);
        tlsOutputStream = new TLSOutputStream(this);

        // start the handshake
        connect();
    }

    public TLSSocket(String host, int port, String proxyHost, int proxyPort) throws IOException {
        this.host = host;
        this.port = port;
        this.proxyHost = proxyHost;
        this.proxyPort = proxyPort;
        m_useProxy = true;

        // get the TLS objects
        record = new Record(this);
        handshake = new Handshake(this);
        tlsInputStream = new TLSInputStream(this);
        tlsOutputStream = new TLSOutputStream(this);

        // start the handshake
        connect();
    }

    protected void connect() throws IOException {
        Socket s;
        if (m_useProxy) {
            s = new Socket(proxyHost, proxyPort);
            doProxyTunnel(s);
        } else {
            s = new Socket(host, port);
        }
        record.setSocket(s);
        handshake.handshake();
        connected = true;
    }

    protected void readAvailable() throws IOException {
        while (record.available()) {
            byte[] frag = record.readRecord();
            if (frag != null) {
                tlsInputStream.addBytes(frag);
            }
        }
    }

    protected void readBlock() throws IOException {
        byte[] frag = record.readRecord();
        if (frag != null) {
            tlsInputStream.addBytes(frag);
        }
    }

    public InputStream getInputStream() { return tlsInputStream; }
    public OutputStream getOutputStream() { return tlsOutputStream; }
    public void close() throws IOException { record.close(); }
    public boolean connected() { return connected; }
    public void setConnected(boolean b) { connected = b; }
    protected Record getRecord() { return record; }

    private void doProxyTunnel(Socket s) throws IOException {
        String req = "CONNECT " + host + ":" + port + " HTTP/1.0\r\n"
            + "User-Agent: TLSSocket By Joel Hockey\r\n"
            + "\r\n";

        s.getOutputStream().write(req.getBytes());
        byte[] buf = new byte[4096];
        int i = s.getInputStream().read(buf);
        if (i < 0) {
            throw new TLSException("Could not read from proxy");
        }

        String res = new String(buf, 0, i);
        if (res.indexOf("200") < 0) {
            throw new TLSException("Could not tunnel through proxy " + proxyHost
                + ":" + proxyPort + ".  Got response " + res);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("usage: TLSSocket <host> <port> <file> [proxyHost] [proxyPort]");
            System.exit(0);
        }

        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String file = args[2];

        TLSSocket tls;
        if (args.length == 3) {
            tls = new TLSSocket(host, port);
        } else {
            String proxyHost = args[3];
            int proxyPort = Integer.parseInt(args[4]);
            tls = new TLSSocket(host, port, proxyHost, proxyPort);
        }

        String out = "GET /" + file  + " HTTP/1.1\r\n"
            + "User-Agent: TLSSocket Test\r\n"
            + "Host: " + host + ":" + port + "\r\n"
            + "Connection: Keep-Alive\r\n"
            + "\r\n";

        tls.getOutputStream().write(out.getBytes());
        byte[] buf = new byte[4096];
        while (true) {
            int count = tls.getInputStream().read(buf);
            if (count < 0) {
                break;
            }
            System.out.print(new String(buf, 0, count));
        }
    }
}