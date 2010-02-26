/*
 * Copyright 2001 Joel Hockey (joel.hockey@gmail.com).  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 * THIS SOURCE CODE IS PROVIDED BY JOEL HOCKEY WITH A 30-DAY MONEY BACK
 * GUARANTEE.  IF THIS CODE DOES NOT MEAN WHAT IT SAYS IT MEANS WITHIN THE
 * FIRST 30 DAYS, SIMPLY RETURN THIS CODE IN ORIGINAL CONDITION FOR A PARTIAL
 * REFUND.  IN ADDITION, I WILL REFORMAT THIS CODE USING YOUR PREFERRED
 * BRACE-POSITIONING AND INDENTATION.  THIS WARRANTY IS VOID IF THE CODE IS
 * FOUND TO HAVE BEEN COMPILED.  NO FURTHER WARRANTY IS OFFERED.
 */

package com.joelhockey.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * Provides a TLS Client Socket connection.  Supports only
 * TLS_RSA_WITH_RC4_128_MD5 without client authentication.
 *
 *	@author		Joel Hockey
 *	@version	$Revision: 1.1 $
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
    //public static final byte[] CIPHER_SUITE = {0x00, 0x02, 0x00, 0x04}; // rc4
    //public static final byte[] CIPHER_SUITE = {0x00, 0x02, 0x00, 0x0a}; // des3
    //public static final byte[] CIPHER_SUITE = {0x00, 0x02, 0x00, 0x2f}; // aes
    
    public static final int KEY_BLOCK_LENGTH = 104;

    // Instance variables.
    private String m_host;
    private int m_port;
    private String m_proxyHost;
    private int m_proxyPort;
    private boolean m_useProxy;
    private Record m_record;
    private Handshake m_handshake;
    private boolean m_connected = false;
    private TLSInputStream m_tlsInputStream;
    private TLSOutputStream m_tlsOutputStream;

    /**
     * Class constructor.
     *
     * @param   host    The server to connect to.
     * @param   port    The port on the server to connect to.
     *
     * @throws TLSException if it cannot establish a connection.
     */
    public TLSSocket(String host, int port) throws IOException {
        m_host = host;
        m_port = port;
        m_useProxy = false;

        // get the TLS objects
        m_record = new Record(this);
        m_handshake = new Handshake(this);
        m_tlsInputStream = new TLSInputStream(this);
        m_tlsOutputStream = new TLSOutputStream(this);

        // start the handshake
        connect();
    }

    public TLSSocket(String host, int port, String proxyHost, int proxyPort) throws IOException {
        m_host = host;
        m_port = port;
        m_proxyHost = proxyHost;
        m_proxyPort = proxyPort;
        m_useProxy = true;

        // get the TLS objects
        m_record = new Record(this);
        m_handshake = new Handshake(this);
        m_tlsInputStream = new TLSInputStream(this);
        m_tlsOutputStream = new TLSOutputStream(this);

        // start the handshake
        connect();
    }

    protected void connect() throws IOException {
        Socket s;
        if (m_useProxy) {
            s = new Socket(m_proxyHost, m_proxyPort);
            doProxyTunnel(s);
        } else {
            s = new Socket(m_host, m_port);
        }
        m_record.setSocket(s);
        m_handshake.handshake();
        m_connected = true;
    }

    protected void readAvailable() throws IOException {
        while (m_record.available()) {
            byte[] frag = m_record.readRecord();
            if (frag != null) {
                m_tlsInputStream.addBytes(frag);
            }
        }
    }

    protected void readBlock() throws IOException {
        byte[] frag = m_record.readRecord();
        if (frag != null) {
            m_tlsInputStream.addBytes(frag);
        }
    }

    /* ========================================================================
     *
     * Methods
     */
    public InputStream getInputStream() { return m_tlsInputStream; }

    public OutputStream getOutputStream() { return m_tlsOutputStream; }

    public void close() throws IOException {
        m_record.close();
    }
    
    public boolean connected() { return m_connected; }

    public void setConnected(boolean b) { m_connected = b; }

    protected Record getRecord() { return m_record; }

    private void doProxyTunnel(Socket s) throws IOException {
        String req = "CONNECT " + m_host + ":" + m_port + " HTTP/1.0\r\n"
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
            throw new TLSException("Could not tunnel through proxy " + m_proxyHost
                + ":" + m_proxyPort + ".  Got response " + res);
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