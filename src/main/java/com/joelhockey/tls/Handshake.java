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

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;

/**
 * Handles the TLS Handshake protocol
 * @author		Joel Hockey
 */
public class Handshake {

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

    private Record record;
    private RSA rsa;
    private MessageDigest md5;
    private MessageDigest sha;
    private MessageDigest tempMD;
    private ByteArrayOutputStream baos;
    private boolean resumingOldSession = false;
    private PRF prf;
    private Random randomGenerator;
    private byte[] clientRandom;
    private byte[] serverRandom;
    private byte[] masterSecret;
    private byte[] sessionID;
    private int cipherSuite;

    // variables used for message buffering
    private byte[] msgs = {};
    private int offset = 0;

    /**
     * Class constructor.
     */
    public Handshake(TLSSocket tlsSocket) throws TLSException {
        try {
            record = tlsSocket.getRecord();
            md5 = MessageDigest.getInstance("MD5");
            sha = MessageDigest.getInstance("SHA");
            baos = new ByteArrayOutputStream();
            prf = new PRF();
            rsa = new RSA();
            randomGenerator = new Random();
        } catch (Exception e) {
            e.printStackTrace();
            throw new TLSException("Error constructing Handshake");
        }
    }

    /**
     * Start the TLS Handshake protocol.
     */
    public void handshake() throws TLSException {
        md5.reset();
        sha.reset();

        sendClientHello();
        readServerHello();
        if (resumingOldSession) {
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

        if (offset == msgs.length) {
            msgs = record.readRecord();
            offset = 0;
        }

        // check if there's enough data to include handshake header
        while (msgs.length < offset + 4) {
            baos.reset();
            baos.write(msgs, offset, msgs.length - offset);
            byte[] temp = record.readRecord();
            baos.write(temp, 0, temp.length);
            msgs = baos.toByteArray();
            offset = 0;
        }

        // get the length
        length = (msgs[offset + 1] & 0xFF) << 16 |
            (msgs[offset + 2] & 0xFF) << 8  | (msgs[offset + 3] & 0xFF);

        // check that there's enough data for message
        while (msgs.length < offset + 4 + length) {
            baos.reset();
            baos.write(msgs, offset, msgs.length - offset);
            byte[] temp = record.readRecord();
            baos.write(temp, 0, temp.length);
            msgs = baos.toByteArray();
            offset = 0;
        }

        byte msg[] = new byte[length + 4];
        System.arraycopy(msgs, offset, msg, 0, length + 4);
        offset += length + 4;
        return msg;
    }

    /**
     * Sends ClientHello
     */
    private void sendClientHello() throws TLSException {
        // Handshake Header.  Set length to zero for now
        baos.reset();
        byte[] header = {CLIENT_HELLO, 0x00, 0x00, 0x00};
        try {
            baos.write(header);

            // create the client Random
            clientRandom = getRandom();

            // Put message in baos
            baos.write(TLSSocket.PROTOCOL_VERSION);
            baos.write(clientRandom);
            if (sessionID == null) {
                baos.write(0);
            } else {
                baos.write((byte) sessionID.length);
                baos.write(sessionID);
            }
            baos.write(TLSSocket.CIPHER_SUITE);
            baos.write(TLSSocket.COMPRESSION_METHOD);
        } catch (Exception e) {
            e.printStackTrace();
            throw new TLSException("Error in Handshake.sendClientHello: " + e.getMessage());
        }

        // convert to an array and set length field, then send it.
        byte[] msg = baos.toByteArray();
        int msgLength = msg.length - 4; // 4 byte header at start
        msg[3] = (byte) msgLength;
        msg[2] = (byte) (msgLength >> 8);
        msg[1] = (byte) (msgLength >> 16);

        updateHashes(msg);
        record.sendMessage(Record.CONTENTTYPE_HANDSHAKE, msg);
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
        if (msg[offset] != TLSSocket.PROTOCOL_VERSION[0] ||
                msg[offset + 1] != TLSSocket.PROTOCOL_VERSION[1]) {

            throw new TLSException("Bad ProtocolVersion in ServerHello");
        }
        offset += 2;

        // get the ServerRandom
        serverRandom = new byte[32];
        System.arraycopy(msg, offset, serverRandom, 0, 32);
        offset += 32;

        // get the SessionID.  First byte is length of sessionID
        int sessionIDLength = msg[offset++];
        byte[] newSessionID = new byte[sessionIDLength];
        System.arraycopy(msg, offset, newSessionID, 0, sessionIDLength);
        offset += sessionIDLength;

        // read cipherSuite
        cipherSuite = msg[offset++] << 8 | msg[offset++];

        // Check if we are resuming an old session.  Assume we are.
        resumingOldSession = true;

        resumingOldSession = Arrays.equals(sessionID, newSessionID);
        sessionID = newSessionID;

        // generate keys now if we're resuming old session
        if (resumingOldSession) {
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
Record.log("all certs len: " + Integer.toHexString(allCertsLength));

        // check that msg is long enough
        int certStop = allCertsLength + offset;
        if (certStop > msg.length) {
            throw new TLSException("Got bad cert vector length field in Certificate");
        }

        // skip first 3 bytes of len
        offset += 3;
        rsa.setCertificates(msg, offset, msg.length - offset);

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
            baos.reset();
            byte[] header = {CLIENT_KEY_EXCHANGE, 0x00, 0x00, 0x00};
            baos.write(header);

            // Set the PreMasterSecret
            byte[] preMasterSecret = new byte[48];
            randomGenerator.nextBytes(preMasterSecret);
            System.arraycopy(TLSSocket.PROTOCOL_VERSION, 0, preMasterSecret, 0, 2);

            // encrypt the PreMasterSecret
            byte[] encrypted = rsa.encrypt(preMasterSecret);

            // write 2 byte len of EncryptedPreMasterSecret vector.
            baos.write(new byte[] {(byte) (encrypted.length >> 8), (byte) encrypted.length});
            baos.write(encrypted);

            // convert ByteArrayOutputStream to ByteArray and set length fields
            byte[] msg = baos.toByteArray();
            int msgLength = msg.length - 4; // 4 byte header at start
            msg[1] = (byte) (msgLength >> 16);
            msg[2] = (byte) (msgLength >> 8);
            msg[3] = (byte) msgLength;

            record.sendMessage(Record.CONTENTTYPE_HANDSHAKE, msg);

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
        record.sendMessage(Record.CONTENTTYPE_CHANGE_CIPHER_SPEC, new byte[]{1});
        record.changeClientWriteState();
    }

    /**
     * Send a Finished message
     */
    private void sendFinished() throws TLSException {
        try {
            baos.reset();
            // Handshake Header.  Set length to 12
            byte[] header = {FINISHED, 0x00, 0x00, 0x0C};
            baos.write(header);

            // concatenate MD5(handshake_messages) and SHA(handshake_messages)
            byte[] temp = new byte[36];
            tempMD = (MessageDigest) md5.clone();
            System.arraycopy(tempMD.digest(), 0, temp, 0, 16);
            tempMD = (MessageDigest) sha.clone();
            System.arraycopy(tempMD.digest(), 0, temp, 16, 20);

            baos.write(prf.getBytes(masterSecret, "client finished", temp, 12));

            byte[] msg = baos.toByteArray();
            record.sendMessage(Record.CONTENTTYPE_HANDSHAKE, msg);

            updateHashes(msg);
        } catch (Exception e) {
            throw new TLSException("Error in Handshake.sendFinished()");
        }
    }

    /**
     * Read a ChangeCipherSpec message.  (The single byte 0x01)
     */
    private void readChangeCipherSpec() throws TLSException {
        byte[] msg = record.readRecord();
        if (msg == null || msg.length != 1 || msg[0] != 0x01) {
            throw new TLSException("Got bad ChangeCipherSpec message");
        }
        record.changeServerWriteState();
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
            tempMD = (MessageDigest) md5.clone();
            System.arraycopy(tempMD.digest(), 0, temp, 0, 16);
            tempMD = (MessageDigest) sha.clone();
            System.arraycopy(tempMD.digest(), 0, temp, 16, 20);
        } catch (Exception e) {
            e.printStackTrace();
            throw new TLSException("Error clongin message digest in Handshake.readFinsihed()");
        }

        byte[] shouldBe = prf.getBytes(masterSecret, "server finished", temp, 12);
Record.log("expected hashes: " + Hex.b2s(shouldBe));

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
     * @return	the Random stuct
     */
    private byte[] getRandom() {
        byte[] random = new byte[32];
        randomGenerator.nextBytes(random);
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
        System.arraycopy(clientRandom, 0, randoms, 0, 32);
        System.arraycopy(serverRandom, 0, randoms, 32, 32);

        masterSecret = prf.getBytes(preMasterSecret, "master secret", randoms, 48);
Record.log("clientRandom   : " + Hex.b2s(clientRandom));
Record.log("serverRandom   : " + Hex.b2s(serverRandom));
Record.log("PreMasterSecret: " + Hex.b2s(preMasterSecret));
Record.log("MasterSecret   : " + Hex.b2s(masterSecret));
    }

    /**
     * Generate read and write keys for the Record layer using the
     * MasterSecret stored in SecurityParameters.
     */
    private void generateKeys() throws TLSException {
        byte[] randoms = new byte[64];

        System.arraycopy(serverRandom, 0, randoms, 0, 32);
        System.arraycopy(clientRandom, 0, randoms, 32, 32);
        byte[] keyBlock = prf.getBytes(masterSecret, "key expansion", randoms, TLSSocket.KEY_BLOCK_LENGTH);

        // set write MAC secrets
Record.log("keyblock       : " + Hex.b2s(keyBlock));
        record.setKeyBlock(cipherSuite, keyBlock);
    }

    /**
     * Update the hashes of all Handshake msg.  This value is needed in
     * the Finished message
     *
     * @param message the message sent or received
     */
    private void updateHashes(byte[] message) {
        md5.update(message);
        sha.update(message);
    }
}
