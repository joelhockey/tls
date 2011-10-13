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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Formats a TLS Record
 *	@author		Joel Hockey
 */
public class Record {
    private static Log log;

    static {
        try {
            // use commons logging if available, else no logging
            log = LogFactory.getLog(Record.class);
        } catch (Throwable t) {} // ignore
    }

    // Class (static) variables.
    public static final byte ALERT_CLOSE_NOTIFY = 0;
    public static final byte ALERT_WARNING = 1;
    public static final byte ALERT_FATAL   = 2;

    public static final byte CONTENTTYPE_CHANGE_CIPHER_SPEC = 20;
    public static final byte CONTENTTYPE_ALERT              = 21;
    public static final byte CONTENTTYPE_HANDSHAKE          = 22;
    public static final byte CONTENTTYPE_APPLICATION_DATA   = 23;

    private static final int MAX_FRAGMENT_LENGTH = 491; // I don't know why?

    // state of reading and writing
    private boolean clientWriteCipherIsNull = true;
    private long clientWriteSeqNum = 0;
    private boolean serverWriteCipherIsNull = true;
    private long serverWriteSeqNum = 0;

    // current state of session
    private TLSSocket tls;
    private HMAC hmacClientWrite;
    private HMAC hmacServerWrite;
    private Cipher encryptCipher;
    private Cipher decryptCipher;
    public OutputStream outs;
    private InputStream ins;
    private int macSize;
    private int blockSize;

    // 18437 is max size of TLS record
    // always try to read an extra 5 bytes to determine if
    // another record fragment is ready
    private byte[] readBuf = new byte[18442];
    private int readBufOffset;

    /**
     * Class constructor.
     */
    public Record(TLSSocket tls) {
        this.tls = tls;
    }


    /**
     * Send a message to the server. One or more records will be written
     * depending on the size of the message.
     *
     * @param contentType   The content type of the message.  Must be valid.
     * @param msg   The message(s) to send
     */
    public void sendMessage(byte contentType, byte[] msg) throws TLSException {
        try {
            // the fragment of the message that gets written each time.
            byte[] fragment = null;

            int msgBytesSent = 0;
            int msgBytesToSend = 0;
            int msgBytesRemaining = msg.length;

            byte[] length = {0, 0};

            // record lengths must be less than MAX_FRAGMENT_LENGTH.
            // We may have to send mulitiple records
            for (;;) {
                if (msgBytesRemaining == 0) {
                    break;
                }

                msgBytesToSend = msgBytesRemaining > MAX_FRAGMENT_LENGTH
                        ? MAX_FRAGMENT_LENGTH : msgBytesRemaining;

                // encrypt if required
                if (!clientWriteCipherIsNull) {
                    byte[] seqNum = l2ba(clientWriteSeqNum++);
                    byte[] mac = getMAC(hmacClientWrite, seqNum, contentType, msg, msgBytesSent, msgBytesToSend);
                    int paddingLen = blockSize == 0 ? 0 : blockSize - ((msgBytesToSend + mac.length) % blockSize);
                    byte[] messageMacPad = new byte[msgBytesToSend + mac.length + paddingLen];
                    System.arraycopy(msg, msgBytesSent, messageMacPad, 0, msgBytesToSend);
                    System.arraycopy(mac, 0, messageMacPad, msgBytesToSend, mac.length);
                    // put padding
                    for (int i = 0; i < paddingLen; i++) {
                        messageMacPad[messageMacPad.length - 1 - i] = (byte) (paddingLen - 1);
                    }
                    try {
log("encrypt input: " + Hex.b2s(messageMacPad));
                        encryptCipher.update(messageMacPad, 0, messageMacPad.length, messageMacPad);
                    } catch (Exception e) {
                        throw new TLSException("encrypt error: " + e.getMessage());
                    }
                    fragment = messageMacPad;

                } else {
                    fragment = new byte[msgBytesToSend];
                    System.arraycopy(msg, msgBytesSent, fragment, 0,
                        msgBytesToSend);
                }
                length[0] = (byte) (fragment.length >> 8);
                length[1] = (byte) fragment.length;

                /* send everything in correct order */
                outs.write(contentType);
                outs.write(TLSSocket.PROTOCOL_VERSION);
                outs.write(length);
                outs.write(fragment);
                outs.flush();

                msgBytesSent += msgBytesToSend;
                msgBytesRemaining -= msgBytesToSend;
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new TLSException("Error sending Record: " + e.getMessage());
        }
    }

    /**
     * Returns the fragment contained in a single Record.
     *
     * The fragment is not necessarily a message.  It may be only part of a
     * message or may be multiple messages.  In most implementations though,
     * it will be one single message.  Returns null if the connection is
     * closed or an error occurs.
     *
     * @return  fragment
     */
     public byte[] readRecord() throws TLSException {
        int recordLength = 0;
        try {
            // read header if required
            while (readBufOffset < 5) { // header is 5 bytes
                int len = ins.read(readBuf, readBufOffset, 5 - readBufOffset);
                if (len == -1) {    // no more data to read
                    tls.setConnected(false);
                    return null;
                }
                readBufOffset += len;
            }

            // check ProtocolVersion
            if (readBuf[1] != TLSSocket.PROTOCOL_VERSION[0]
                    || readBuf[2] != TLSSocket.PROTOCOL_VERSION[1]) {
log("Bad Protocol Version in Record Header 0x" + Hex.b2s(readBuf, 0, 5));
                throw new TLSException("Bad Protocol Version in Record Header 0x"
                    + Hex.b2s(readBuf, 0, 5));
            }

            // get the length
            recordLength = (readBuf[3] & 0xFF) << 8 | (readBuf[4] & 0xFF);

            // read the rest
            while (readBufOffset < recordLength + 5) {
                // try to read an extra 5 bytes here to see if more fragments ready
                int len = ins.read(readBuf, readBufOffset, recordLength + 10 - readBufOffset);
                if (len < 0) {
                    throw new TLSException("Bad Record Received");
                }
                readBufOffset += len;
            }
log("record read: (" + recordLength + ") " + Hex.b2s(readBuf, 0, 5 + recordLength));
        } catch (TLSException tlse) {
            throw tlse;
        } catch (SocketException e) {   // connection closed
            e.printStackTrace();
            tls.setConnected(false);
            return null;
        } catch (IOException e) {
            e.printStackTrace();
            throw new TLSException("Error in Record.readRecord()");
        }

        byte[] fragment = new byte[recordLength];

        // decrypt if !ServerWriteCipherIsNull
        if (!serverWriteCipherIsNull) {
            try {
                decryptCipher.update(readBuf, 5, recordLength, fragment);
            } catch (Exception e) {
            }

            int fragmentLength = recordLength - macSize;
            // subtract padding from fragmentLength
            if (blockSize > 0) {
                fragmentLength -= ((fragment[recordLength - 1] & 0xff) + 1);
            }

            byte[] seqNum = l2ba(serverWriteSeqNum++);
            byte[] mac = getMAC(hmacServerWrite, seqNum, readBuf[0], fragment, 0, fragmentLength);
log("expected mac: " + Hex.b2s(mac));

            for (int i = 0; i < mac.length; i++) {
                if (fragment[fragmentLength + i] != mac[i]) {
log("Bad MAC received:\ndecrypted fragment with pad: " + Hex.b2s(fragment, 0, recordLength));
                    throw new TLSException("Bad MAC received: decrypted fragment: " + Hex.b2s(fragment, 0, recordLength));
                }
            }

log("mac good!");
            byte[] fragmentNoMac = new byte[fragmentLength];
            System.arraycopy(fragment, 0, fragmentNoMac, 0, fragmentLength);
            fragment = fragmentNoMac;

        } else {
            System.arraycopy(readBuf, 5, fragment, 0, recordLength);
        }

        // check ContentType
        if (readBuf[0] == CONTENTTYPE_ALERT) {
            if (fragment.length != 2) {
                throw new TLSException("Badly formed Alert message received");
            }

            if (fragment[1] != ALERT_CLOSE_NOTIFY) {
                throw new TLSException("Unsupported Alert received : 0x" + Hex.b2s(fragment));
            }

            sendMessage(CONTENTTYPE_ALERT, new byte[] {ALERT_WARNING, ALERT_CLOSE_NOTIFY});
            tls.setConnected(false);
            return null;
        }

        // reset m_readBufOffset
        // copy any extra data (like the next 5 bytes of a record header) to front of m_readBuf
        if (readBufOffset > recordLength + 5) {
            System.arraycopy(readBuf, recordLength + 5, readBuf, 0, readBufOffset - (recordLength + 5));
        }
        readBufOffset -= (recordLength + 5);

        return fragment;
    }

    /**
     * Promote the pending write state to be the current state
     */
    public void changeClientWriteState() {
        clientWriteCipherIsNull = false;
    }

    /**
     * Promote the pending read state to be the current state
     */
    public void changeServerWriteState() {
        serverWriteCipherIsNull = false;
    }

    /**
     * Sets the key block for the pending state.
     *
     * @param keyBlock  enough material to set all keys
     */
    public void setKeyBlock(int cipherSuite, byte[] keyBlock) {
        try {
            // assume TLS_RSA_WITH_RC4_128_MD5
            macSize = 16;
            blockSize = 0;
            int keySize = 16;
            int ivSize = 0;
            String keyAlg = "RC4";
            String cipherAlg = "RC4";
            String macAlg = "MD5";

            if (cipherSuite == TLSSocket.TLS_RSA_WITH_3DES_EDE_CBC_SHA) {
                cipherAlg = "DESede/CBC/NoPadding";
                keyAlg = "DESede";
                macAlg = "SHA-1";
                macSize = 20;
                blockSize = 8;
                keySize = 24;
                ivSize = 8;
            } else if (cipherSuite == TLSSocket.TLS_RSA_WITH_AES_128_CBC_SHA) {
                cipherAlg = "AES/CBC/NoPadding";
                keyAlg = "AES";
                macAlg = "SHA-1";
                macSize = 20;
                blockSize = 16;
                keySize = 16;
                ivSize = 16;
            }

            byte[] clientWriteMACSecret = sub(keyBlock, 0, macSize);
            byte[] serverWriteMACSecret = sub(keyBlock, macSize, macSize);
            byte[] clientWriteKey = sub(keyBlock, 2 * macSize, keySize);
            byte[] serverWriteKey = sub(keyBlock, 2 * macSize + keySize, keySize);
            byte[] clientWriteIV = sub(keyBlock, 2 * (macSize + keySize), ivSize);
            byte[] serverWriteIV = sub(keyBlock, 2 * (macSize + keySize) + ivSize, ivSize);

            hmacClientWrite = new HMAC(MessageDigest.getInstance(macAlg), clientWriteMACSecret);
            hmacServerWrite = new HMAC(MessageDigest.getInstance(macAlg), serverWriteMACSecret);

            encryptCipher = Cipher.getInstance(cipherAlg);
            decryptCipher = Cipher.getInstance(cipherAlg);

            // no IV for RC4
            if (cipherSuite == TLSSocket.TLS_RSA_WITH_RC4_128_MD5) {
                encryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(clientWriteKey, keyAlg));
                decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(serverWriteKey, keyAlg));
            } else {
                encryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(clientWriteKey, keyAlg), new IvParameterSpec(clientWriteIV));
                decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(serverWriteKey, keyAlg), new IvParameterSpec(serverWriteIV));
            }
log("client write key: " + Hex.b2s(clientWriteKey));
log("client write iv : " + Hex.b2s(clientWriteIV));
log("server write key: " + Hex.b2s(serverWriteKey));
log("server write iv : " + Hex.b2s(serverWriteIV));

        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Set the connect cipher states to null and writeSeqNums to zero.  Create
     * new socket connection to server
     */
    public void setSocket(Socket s) throws TLSException {
        try {
            clientWriteCipherIsNull = true;
            serverWriteCipherIsNull = true;
            clientWriteSeqNum = 0;
            serverWriteSeqNum = 0;
            outs = new BufferedOutputStream(s.getOutputStream());
            ins = new BufferedInputStream(s.getInputStream());
        } catch (Exception e) {
            e.printStackTrace();
            throw new TLSException("Error in Record.reset(): " + e.getMessage());
        }
    }

    /**
     * Return the value of the available method on the underlying socket
     * connection.
     */
    public boolean available() {
        return readBufOffset > 0;
    }

    public void close() throws IOException {
        sendMessage(CONTENTTYPE_ALERT, new byte[] {ALERT_WARNING, ALERT_CLOSE_NOTIFY});
        outs.close();
    }

    /**
     * Return the MAC of the given byte array using the protocol specified
     * in TLSSocket
     *
     * @param end Either SecurityParameters.CONNECTIONEND_CLIENT or
     *      SecurityParameters.CONNECTIONEND_SERVER.  Indicates whether to use
     *      ServerWrite keys or ClientWrite keys for calculating MAC
     * @param type      content type of message
     * @param buf       the byte array containing the message to get the MAC of.
     * @param offset    where the message starts
     * @param length    the length of the message
     *
     * @return the MAC
     */
     private byte[] getMAC(HMAC hmac, byte[] seqNum, byte type, byte[] message, int offset, int length) {

        // concatenate all values to be MACed,
        // seqNum (8) + ContentType (1) + version (2) + message vector (2 len, msg.length)
        byte[] input = new byte[13 + length];
        System.arraycopy(seqNum, 0, input, 0, 8);
        input[8] = type;
        System.arraycopy(TLSSocket.PROTOCOL_VERSION, 0, input, 9, 2);
        input[11] = (byte) (length >> 8);
        input[12] = (byte) (length);
        System.arraycopy(message, offset, input, 13, length);

log("input to mac: " + Hex.b2s(input));

        // MAC them
        return hmac.digest(input);
    }

    // Converts long to byte array
    private byte[] l2ba(long l) {
        byte[] byteVal = new byte[8];
        byteVal[7] = (byte) (l);
        byteVal[6] = (byte) (l >> 8);
        byteVal[5] = (byte) (l >> 16);
        byteVal[4] = (byte) (l >> 24);
        byteVal[3] = (byte) (l >> 32);
        byteVal[2] = (byte) (l >> 40);
        byteVal[1] = (byte) (l >> 48);
        byteVal[0] = (byte) (l >> 56);
        return byteVal;
    }

    private static byte[] sub(byte[] buf, int offset, int len) {
        byte[] result = new byte[len];
        System.arraycopy(buf, offset, result, 0, len);
        return result;
    }

    static void log(String msg) {
        if (log != null) {
            log.debug(msg);
        }
    }
}