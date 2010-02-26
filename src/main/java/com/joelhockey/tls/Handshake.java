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

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Handles the TLS Handshake protocol
 *
 * @author		Joel Hockey
 */
public class Handshake {
    private static final Log log = LogFactory.getLog(Handshake.class);
    // Class variables.

    // Header types
    private final byte HELLO_REQUEST       = 0;
    private final byte CLIENT_HELLO        = 1;
    private final byte SERVER_HELLO        = 2;
    private final byte CERTIFICATE         = 11;
    private final byte SERVER_KEY_EXCHANGE = 12;
    private final byte CERTIFICATE_REQUEST = 13;
    private final byte SERVER_HELLO_DONE   = 14;
    private final byte CERTIFICATE_VERIFY  = 15;
    private final byte CLIENT_KEY_EXCHANGE = 16;
    private final byte FINISHED            = 20;

    // Instance variables.

    private TLSSocket m_tlsSocket;
    private Record m_record;
    private RSA m_rsa;
    private MessageDigest m_md5;
    private MessageDigest m_sha;
    private MessageDigest m_tempMD;
    private ByteArrayOutputStream m_baos;
    private boolean m_resumingOldSession = false;
    private PRF m_prf;
    private Random m_randomGenerator;
    private byte[] m_clientRandom;
    private byte[] m_serverRandom;
    private byte[] m_masterSecret;
    private byte[] m_sessionID;
    private int m_cipherSuite;

    // variables used for message buffering
    private byte[] m_msgs = {};
    private int m_offset = 0;

    /**
     * Class constructor.
     */
    public Handshake(TLSSocket tlsSocket) throws TLSException {
        try {
            m_tlsSocket = tlsSocket;
            m_record = tlsSocket.getRecord();
            m_md5 = MessageDigest.getInstance("MD5");
            m_sha = MessageDigest.getInstance("SHA");
            m_baos = new ByteArrayOutputStream();
            m_prf = new PRF();
            m_rsa = new RSA();
            m_randomGenerator = new Random();
        } catch (Exception e) {
            e.printStackTrace();
            throw new TLSException("Error constructing Handshake");
        }
    }

    /**
     * Start the TLS Handshake protocol.
     */
    public void handshake() throws TLSException {
        m_md5.reset();
        m_sha.reset();

        sendClientHello();
        readServerHello();
        if (m_resumingOldSession) {
            readChangeCipherSpec();
            readFinished();
            sendChangeCipherSpec();
            sendFinished();
        } else {
            readCertificate();
            readServerHelloDone();
            sendClientKeyExchange();
            sendChangeCipherSpec();
            sendFinished();
            readChangeCipherSpec();
            readFinished();
        }
    }

    // Private methods

    /**
     * Acts as a buffer for handshake messages.  Checks that length field
     * is valid.
     */
    private byte[] getMsg() throws TLSException {
        int length = 0;

        if (m_offset == m_msgs.length) {
            m_msgs = m_record.readRecord();
            m_offset = 0;
        }

        // check if there's enough data to include handshake header
        while (m_msgs.length < m_offset + 4) {
            m_baos.reset();
            m_baos.write(m_msgs, m_offset, m_msgs.length - m_offset);
            byte[] temp = m_record.readRecord();
            m_baos.write(temp, 0, temp.length);
            m_msgs = m_baos.toByteArray();
            m_offset = 0;
        }

        // get the length
        length = (m_msgs[m_offset + 1] & 0xFF) << 16 |
            (m_msgs[m_offset + 2] & 0xFF) << 8  | (m_msgs[m_offset + 3] & 0xFF);

        // check that there's enough data for message
        while (m_msgs.length < m_offset + 4 + length) {
            m_baos.reset();
            m_baos.write(m_msgs, m_offset, m_msgs.length - m_offset);
            byte[] temp = m_record.readRecord();
            m_baos.write(temp, 0, temp.length);
            m_msgs = m_baos.toByteArray();
            m_offset = 0;
        }

        byte msg[] = new byte[length + 4];
        System.arraycopy(m_msgs, m_offset, msg, 0, length + 4);
        m_offset += length + 4;
        return msg;
    }

    /**
     * Sends ClientHello
     */
    private void sendClientHello() throws TLSException {
        // Handshake Header.  Set length to zero for now
        m_baos.reset();
        byte[] header = {CLIENT_HELLO, 0x00, 0x00, 0x00};
        try {
            m_baos.write(header);

            // create the client Random
            m_clientRandom = getRandom();

            // Put message in baos
            m_baos.write(m_tlsSocket.PROTOCOL_VERSION);
            m_baos.write(m_clientRandom);
            if (m_sessionID == null) {
                m_baos.write(0);
            } else {
                m_baos.write((byte) m_sessionID.length);
                m_baos.write(m_sessionID);
            }
            m_baos.write(m_tlsSocket.CIPHER_SUITE);
            m_baos.write(m_tlsSocket.COMPRESSION_METHOD);
//m_baos.reset();
//m_clientRandom = new byte[] {
//        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
//        3,1,4,1,5,9,2,6,5,3,5,8,9,7,9,3};
//byte[] v2hello = {
//        0x01, // clienthello
//        0x03,0x01, // 3.1
//        0x00,0x03, // cipherSpecLen
//        0x00,0x00, // sessionIdLen
//        0x00,0x10, // challenge len
//        0x00,0x00,0x0a, // cipher des3-cbc-sha
//        3,1,4,1,5,9,2,6,5,3,5,8,9,7,9,3 // 16 challenge data
//};
//updateHashes(v2hello);
//byte[] v2helloWithHeader = new byte[v2hello.length + 2];
//v2helloWithHeader[0] = (byte) 0x80;
//v2helloWithHeader[1] = (byte) v2hello.length;
//System.arraycopy(v2hello, 0, v2helloWithHeader, 2, v2hello.length);
//m_record.m_os.write(v2helloWithHeader);
//m_record.m_os.flush();
//if (true) return;
        } catch (Exception e) {
            e.printStackTrace();
            throw new TLSException("Error in Handshake.sendClientHello: " + e.getMessage());
        }

        // convert to an array and set length field, then send it.
        byte[] msg = m_baos.toByteArray();
        int msgLength = msg.length - 4; // 4 byte header at start
        msg[3] = (byte) msgLength;
        msg[2] = (byte) (msgLength >> 8);
        msg[1] = (byte) (msgLength >> 16);

        updateHashes(msg);
        m_record.sendMessage(Record.CONTENTTYPE_HANDSHAKE, msg);
    }

    /**
     * Read ServerHello
     */
    private void readServerHello() throws TLSException {

        byte[] msg = getMsg();
        int offset = 0;

        // check that first byte is ServerHello Handshake Type
        if (msg[offset] != SERVER_HELLO) {
            throw new TLSException("Did not get the expected ServerHello message");
        }

        offset += 4;    // skip header

        // Read the ServerHello
        // check ProtocolVersion
        if (msg[offset] != m_tlsSocket.PROTOCOL_VERSION[0] ||
                msg[offset + 1] != m_tlsSocket.PROTOCOL_VERSION[1]) {

            throw new TLSException("Bad ProtocolVersion in ServerHello");
        }
        offset += 2;

        // get the ServerRandom
        m_serverRandom = new byte[32];
        System.arraycopy(msg, offset, m_serverRandom, 0, 32);
        offset += 32;

        // get the SessionID.  First byte is length of sessionID
        int sessionIDLength = msg[offset++];
        byte[] sessionID = new byte[sessionIDLength];
        System.arraycopy(msg, offset, sessionID, 0, sessionIDLength);
        offset += sessionIDLength;
        
        // read cipherSuite
        m_cipherSuite = msg[offset++] << 8 | msg[offset++];

        // Check if we are resuming an old session.  Assume we are.
        m_resumingOldSession = true;

        m_resumingOldSession = Arrays.equals(m_sessionID, sessionID);
        m_sessionID = sessionID;

        // generate keys now if we're resuming old session
        if (m_resumingOldSession) {
            generateKeys();
        }

        updateHashes(msg);
    }

    /**
     * Read a Certificate.  Reads the first certificate in the chain.  Does
     * NOT verify the certificate AT ALL.
     */
    private void readCertificate() throws TLSException {
        byte[] msg = getMsg();
        int offset = 0;

        // check that first byte is ServerCertificate Handshake Type
        if (msg[offset] != CERTIFICATE) {
            throw new TLSException("Did not get the expected Certificate message");
        }

        offset += 4;    // skip header

        // get length of all certificates
        int allCertsLength = (msg[offset] & 0xFF) << 16
                | (msg[offset + 1] & 0xFF) << 8
                | (msg[offset + 2] & 0xFF);
        offset += 3;
log.debug("all certs len: " + Integer.toHexString(allCertsLength));

        // check that msg is long enough
        int certStop = allCertsLength + offset;
        if (certStop > msg.length) {
            throw new TLSException("Got bad cert vector length field in Certificate");
        }

        // skip first 3 bytes of len
        offset += 3;
        m_rsa.setCertificates(msg, offset, msg.length - offset);

        updateHashes(msg);
    }

    /**
     * Read ServerHelloDone
     */
    private void readServerHelloDone() throws TLSException {
        byte[] msg = getMsg();

        // check that first byte is ServerHelloDone Handshake Type
        if (msg[0] != SERVER_HELLO_DONE) {
            throw new TLSException("Did not get the expected ServerHelloDone message");
        }

        // check that message is good
        if (msg.length != 4 || msg[1] != 0x00 || msg[2] != 0x00
                || msg[3] != 0x00) {
            throw new TLSException("Bad length in ServerHelloDone");
        }

        updateHashes(msg);
    }

    /**
     * Send ClientKeyExchange
     */
    private void sendClientKeyExchange() throws TLSException {
        try {
            // Handshake Header.  Set length to zero for now
            m_baos.reset();
            byte[] header = {CLIENT_KEY_EXCHANGE, 0x00, 0x00, 0x00};
            m_baos.write(header);

            // Set the PreMasterSecret
            byte[] preMasterSecret = new byte[48];
            m_randomGenerator.nextBytes(preMasterSecret);
            System.arraycopy(m_tlsSocket.PROTOCOL_VERSION, 0, preMasterSecret, 0, 2);

            // encrypt the PreMasterSecret
            byte[] encrypted = m_rsa.encrypt(preMasterSecret); 
            
            // write 2 byte len of EncryptedPreMasterSecret vector.
            m_baos.write(new byte[] {(byte) (encrypted.length >> 8), (byte) encrypted.length});
            m_baos.write(encrypted);
            
            // convert ByteArrayOutputStream to ByteArray and set length fields
            byte[] msg = m_baos.toByteArray();
            int msgLength = msg.length - 4; // 4 byte header at start
            msg[1] = (byte) (msgLength >> 16);
            msg[2] = (byte) (msgLength >> 8);
            msg[3] = (byte) msgLength;

            m_record.sendMessage(Record.CONTENTTYPE_HANDSHAKE, msg);

            // generate MasterSecret and keys
            generateMasterSecret(preMasterSecret);
            generateKeys();

            updateHashes(msg);
        } catch (Exception e) {
            e.printStackTrace();
            throw new TLSException("Error in Handshake.sendClientKeyExchange(): " + e.getMessage());
        }
    }

    /**
     * Send the ChangeCipherSpec message
     */
    private void sendChangeCipherSpec() throws TLSException {
        // No headers here, just one byte to send, the value 0x01.
        m_record.sendMessage(Record.CONTENTTYPE_CHANGE_CIPHER_SPEC, new byte[]{1});
        m_record.changeClientWriteState();
    }

    /**
     * Send a Finished message
     */
    private void sendFinished() throws TLSException {
        try {
            m_baos.reset();
            // Handshake Header.  Set length to 12
            byte[] header = {FINISHED, 0x00, 0x00, 0x0C};
            m_baos.write(header);

            // concatenate MD5(handshake_messages) and SHA(handshake_messages)
            byte[] temp = new byte[36];
            m_tempMD = (MessageDigest) m_md5.clone();
            System.arraycopy(m_tempMD.digest(), 0, temp, 0, 16);
            m_tempMD = (MessageDigest) m_sha.clone();
            System.arraycopy(m_tempMD.digest(), 0, temp, 16, 20);

            m_baos.write(m_prf.getBytes(m_masterSecret, "client finished", temp, 12));

            byte[] msg = m_baos.toByteArray();
            m_record.sendMessage(Record.CONTENTTYPE_HANDSHAKE, msg);

            updateHashes(msg);
        } catch (Exception e) {
            throw new TLSException("Error in Handshake.sendFinished()");
        }
    }

    /**
     * Read a ChangeCipherSpec message.  (The single byte 0x01)
     */
    private void readChangeCipherSpec() throws TLSException {
        byte[] msg = m_record.readRecord();
        if (msg == null || msg.length != 1 || msg[0] != 0x01) {
            throw new TLSException("Got bad ChangeCipherSpec message");
        }
        m_record.changeServerWriteState();
    }

    /**
     * Read Finished
     */
    private void readFinished() throws TLSException {
        byte[] msg = getMsg();
        int offset = 0;

        // check that first byte is ServerHello Handshake Type
        if (msg[offset] != FINISHED) {
            throw new TLSException("Did not get the expected Finished message");
        }

        offset += 4;    // skip header

        // check that length == 12
        if (msg.length != 16) {
            throw new TLSException("Bad length field in Finished message");
        }

        byte[] temp = new byte[36];
        try {
            // concatenate MD5(handshake_msg) and SHA(handshake_msg)
            m_tempMD = (MessageDigest) m_md5.clone();
            System.arraycopy(m_tempMD.digest(), 0, temp, 0, 16);
            m_tempMD = (MessageDigest) m_sha.clone();
            System.arraycopy(m_tempMD.digest(), 0, temp, 16, 20);
        } catch (Exception e) {
            e.printStackTrace();
            throw new TLSException("Error clongin message digest in Handshake.readFinsihed()");
        }

        byte[] shouldBe = m_prf.getBytes(m_masterSecret, "server finished", temp, 12);
log.debug("expected hashes: " + Hex.b2s(shouldBe));

        // verify the 12 bytes
        for (int i = 0; i < 12; i++) {
            if (msg[i + 4] != shouldBe[i]) {
                throw new TLSException("Bad VerifyData from Server");
            }
        }
        updateHashes(msg);
    }

    /**
     * Returns the Random struct as a byte array
     *
     * @return	the Random stuct
     *
     */
    private byte[] getRandom() {
        byte[] random = new byte[32];
        m_randomGenerator.nextBytes(random);
        long gmt_unix_time = System.currentTimeMillis() / 1000;
        random[3] = (byte) gmt_unix_time;
        random[2] = (byte) (gmt_unix_time >> 8);
        random[1] = (byte) (gmt_unix_time >> 16);
        random[0] = (byte) (gmt_unix_time >> 24);
        return random;
    }

    /**
     * Generate a master secret from the given preMasterSecret and store
     * it in SecurityParameters
     */
    private void generateMasterSecret(byte[] preMasterSecret) throws TLSException {
        byte[] randoms = new byte[64];
        System.arraycopy(m_clientRandom, 0, randoms, 0, 32);
        System.arraycopy(m_serverRandom, 0, randoms, 32, 32);

        m_masterSecret = m_prf.getBytes(preMasterSecret, "master secret", randoms, 48);
log.debug("clientRandom   : " + Hex.b2s(m_clientRandom));
log.debug("serverRandom   : " + Hex.b2s(m_serverRandom));
log.debug("PreMasterSecret: " + Hex.b2s(preMasterSecret));
log.debug("MasterSecret   : " + Hex.b2s(m_masterSecret));
    }

    /**
     * Generate read and write keys for the Record layer using the
     * MasterSecret stored in SecurityParameters.
     */
    private void generateKeys() throws TLSException {
        byte[] randoms = new byte[64];

        System.arraycopy(m_serverRandom, 0, randoms, 0, 32);
        System.arraycopy(m_clientRandom, 0, randoms, 32, 32);
        byte[] keyBlock = m_prf.getBytes(m_masterSecret, "key expansion", randoms, TLSSocket.KEY_BLOCK_LENGTH);

        // set write MAC secrets
log.debug("keyblock       : " + Hex.b2s(keyBlock));
        m_record.setKeyBlock(m_cipherSuite, keyBlock);
    }

    /**
     * Update the hashes of all Handshake msg.  This value is needed in
     * the Finished message
     *
     * @param message the message sent or received
     */
    private void updateHashes(byte[] message) {
        m_md5.update(message);
        m_sha.update(message);
    }

    
public static void main(String[] args) throws Exception { TLSSocket.main(args); }
}
