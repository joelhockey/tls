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
 *
 *	@author		Joel Hockey
 *	@version	$Revision: 1.2 $
 */
public class Record {
    private static final Log log = LogFactory.getLog(Record.class);

    // Class (static) variables.
    public static final byte ALERT_CLOSE_NOTIFY = 0;
    public static final byte ALERT_WARNING = 1;
    public static final byte ALERT_FATAL   = 2;

    public static final byte CONTENTTYPE_CHANGE_CIPHER_SPEC = 20;
    public static final byte CONTENTTYPE_ALERT              = 21;
    public static final byte CONTENTTYPE_HANDSHAKE          = 22;
    public static final byte CONTENTTYPE_APPLICATION_DATA   = 23;

    private static final int MAX_FRAGMENT_LENGTH = 491; // I don't know why?

    // Instance variables.

    // state of reading and writing
    private boolean m_clientWriteCipherIsNull = true;
    private long m_clientWriteSeqNum = 0;
    private boolean m_serverWriteCipherIsNull = true;
    private long m_serverWriteSeqNum = 0;

    // current state of session
    private TLSSocket m_tls;
    private HMAC m_hmacClientWrite;
    private HMAC m_hmacServerWrite;
    private Cipher m_encryptCipher;
    private Cipher m_decryptCipher;
    public OutputStream m_os;
    private InputStream m_is;
    private int m_macSize;
    private int m_blockSize;

    // 18437 is max size of TLS record
    // always try to read an extra 5 bytes to determine if
    // another record fragment is ready
    private byte[] m_readBuf = new byte[18442];
    private int m_readBufOffset;

    /**
     * Class constructor.
     */
    public Record(TLSSocket tls) throws TLSException {
        m_tls = tls;
    }


    /* ========================================================================
     *
     * Methods
     */

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
                if (!m_clientWriteCipherIsNull) {
                    byte[] seqNum = l2ba(m_clientWriteSeqNum++);
                    byte[] mac = getMAC(m_hmacClientWrite, seqNum, contentType, msg, msgBytesSent, msgBytesToSend);
                    int paddingLen = m_blockSize == 0 ? 0 : m_blockSize - ((msgBytesToSend + mac.length) % m_blockSize);
                    byte[] messageMacPad = new byte[msgBytesToSend + mac.length + paddingLen];
                    System.arraycopy(msg, msgBytesSent, messageMacPad, 0, msgBytesToSend);
                    System.arraycopy(mac, 0, messageMacPad, msgBytesToSend, mac.length);
                    // put padding
                    for (int i = 0; i < paddingLen; i++) {
                        messageMacPad[messageMacPad.length - 1 - i] = (byte) (paddingLen - 1);
                    }
                    try {
log.debug("encrypt input: " + Hex.b2s(messageMacPad));
                        m_encryptCipher.update(messageMacPad, 0, messageMacPad.length, messageMacPad);
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
                m_os.write(contentType);
                m_os.write(TLSSocket.PROTOCOL_VERSION);
                m_os.write(length);
                m_os.write(fragment);
                m_os.flush();

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
            while (m_readBufOffset < 5) { // header is 5 bytes
                int len = m_is.read(m_readBuf, m_readBufOffset, 5 - m_readBufOffset);
                if (len == -1) {    // no more data to read
                    m_tls.setConnected(false);
                    return null;
                }
                m_readBufOffset += len;
            }

            // check ProtocolVersion
            if (m_readBuf[1] != TLSSocket.PROTOCOL_VERSION[0]
                    || m_readBuf[2] != TLSSocket.PROTOCOL_VERSION[1]) {
log.error("Bad Protocol Version in Record Header 0x" + Hex.b2s(m_readBuf, 0, 5));
                throw new TLSException("Bad Protocol Version in Record Header 0x"
                    + Hex.b2s(m_readBuf, 0, 5));
            }

            // get the length
            recordLength = (m_readBuf[3] & 0xFF) << 8 | (m_readBuf[4] & 0xFF);

            // read the rest
            while (m_readBufOffset < recordLength + 5) {
                // try to read an extra 5 bytes here to see if more fragments ready
                int len = m_is.read(m_readBuf, m_readBufOffset, recordLength + 10 - m_readBufOffset);
                if (len < 0) {
                    throw new TLSException("Bad Record Received");
                }
                m_readBufOffset += len;
            }
log.debug("record read: (" + recordLength + ") " + Hex.b2s(m_readBuf, 0, 5 + recordLength));
        } catch (TLSException tlse) {
            throw tlse;
        } catch (SocketException e) {   // connection closed
            e.printStackTrace();
            m_tls.setConnected(false);
            return null;
        } catch (IOException e) {
            e.printStackTrace();
            throw new TLSException("Error in Record.readRecord()");
        }

        byte[] fragment = new byte[recordLength];

        // decrypt if !ServerWriteCipherIsNull
        if (!m_serverWriteCipherIsNull) {
            try {
                m_decryptCipher.update(m_readBuf, 5, recordLength, fragment);
            } catch (Exception e) {
            }
            
            int fragmentLength = recordLength - m_macSize;
            // subtract padding from fragmentLength
            if (m_blockSize > 0) {
                fragmentLength -= ((fragment[recordLength - 1] & 0xff) + 1);
            }
            
            byte[] seqNum = l2ba(m_serverWriteSeqNum++);
            byte[] mac = getMAC(m_hmacServerWrite, seqNum, m_readBuf[0], fragment, 0, fragmentLength);
log.debug("expected mac: " + Hex.b2s(mac));

            for (int i = 0; i < mac.length; i++) {
                if (fragment[fragmentLength + i] != mac[i]) {
log.error("Bad MAC received:\ndecrypted fragment with pad: " + Hex.b2s(fragment, 0, recordLength));
                    throw new TLSException("Bad MAC received: decrypted fragment: " + Hex.b2s(fragment, 0, recordLength));
                }
            }

log.debug("mac good!");
            byte[] fragmentNoMac = new byte[fragmentLength];
            System.arraycopy(fragment, 0, fragmentNoMac, 0, fragmentLength);
            fragment = fragmentNoMac;     
            
        } else {
            System.arraycopy(m_readBuf, 5, fragment, 0, recordLength);
        }

        // check ContentType
        if (m_readBuf[0] == CONTENTTYPE_ALERT) {
            if (fragment.length != 2) {
                throw new TLSException("Badly formed Alert message received");
            }

            if (fragment[1] != ALERT_CLOSE_NOTIFY) {
                throw new TLSException("Unsupported Alert received : 0x" + Hex.b2s(fragment));
            }

            sendMessage(CONTENTTYPE_ALERT, new byte[] {ALERT_WARNING, ALERT_CLOSE_NOTIFY});
            m_tls.setConnected(false);
            return null;
        }

        // reset m_readBufOffset
        // copy any extra data (like the next 5 bytes of a record header) to front of m_readBuf
        if (m_readBufOffset > recordLength + 5) {
            System.arraycopy(m_readBuf, recordLength + 5, m_readBuf, 0, m_readBufOffset - (recordLength + 5));
        }
        m_readBufOffset -= (recordLength + 5);
        
        return fragment;
    }

    /**
     * Promote the pending write state to be the current state
     */
    public void changeClientWriteState() {
        m_clientWriteCipherIsNull = false;
    }

    /**
     * Promote the pending read state to be the current state
     */
    public void changeServerWriteState() {
        m_serverWriteCipherIsNull = false;
    }

    /**
     * Sets the key block for the pending state.
     *
     * @param keyBlock  enough material to set all keys
     */
    public void setKeyBlock(int cipherSuite, byte[] keyBlock) {
        try {
            // assume TLS_RSA_WITH_RC4_128_MD5
            m_macSize = 16;
            m_blockSize = 0;
            int keySize = 16;
            int ivSize = 0;
            String keyAlg = "RC4";
            String cipherAlg = "RC4";
            String macAlg = "MD5";
            
            if (cipherSuite == TLSSocket.TLS_RSA_WITH_3DES_EDE_CBC_SHA) {
                cipherAlg = "DESede/CBC/NoPadding";
                keyAlg = "DESede";
                macAlg = "SHA-1";
                m_macSize = 20;
                m_blockSize = 8;
                keySize = 24;
                ivSize = 8;
            } else if (cipherSuite == TLSSocket.TLS_RSA_WITH_AES_128_CBC_SHA) {
                cipherAlg = "AES/CBC/NoPadding";
                keyAlg = "AES";
                macAlg = "SHA-1";
                m_macSize = 20;
                m_blockSize = 16;
                keySize = 16;
                ivSize = 16;
            }
            
            byte[] clientWriteMACSecret = sub(keyBlock, 0, m_macSize);
            byte[] serverWriteMACSecret = sub(keyBlock, m_macSize, m_macSize);
            byte[] clientWriteKey = sub(keyBlock, 2 * m_macSize, keySize);
            byte[] serverWriteKey = sub(keyBlock, 2 * m_macSize + keySize, keySize);
            byte[] clientWriteIV = sub(keyBlock, 2 * (m_macSize + keySize), ivSize);
            byte[] serverWriteIV = sub(keyBlock, 2 * (m_macSize + keySize) + ivSize, ivSize);

            m_hmacClientWrite = new HMAC(MessageDigest.getInstance(macAlg), clientWriteMACSecret);
            m_hmacServerWrite = new HMAC(MessageDigest.getInstance(macAlg), serverWriteMACSecret);
            
            m_encryptCipher = Cipher.getInstance(cipherAlg);
            m_encryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(clientWriteKey, keyAlg), new IvParameterSpec(clientWriteIV));

            m_decryptCipher = Cipher.getInstance(cipherAlg);
            m_decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(serverWriteKey, keyAlg), new IvParameterSpec(serverWriteIV));
log.debug("client write key: " + Hex.b2s(clientWriteKey));
log.debug("client write iv : " + Hex.b2s(clientWriteIV));
log.debug("server write key: " + Hex.b2s(serverWriteKey));
log.debug("server write iv : " + Hex.b2s(serverWriteIV));

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
            m_clientWriteCipherIsNull = true;
            m_serverWriteCipherIsNull = true;
            m_clientWriteSeqNum = 0;
            m_serverWriteSeqNum = 0;
            m_os = new BufferedOutputStream(s.getOutputStream());
            m_is = new BufferedInputStream(s.getInputStream());
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
        return m_readBufOffset > 0;
    }

    public void close() throws IOException {
        sendMessage(CONTENTTYPE_ALERT, new byte[] {ALERT_WARNING, ALERT_CLOSE_NOTIFY});
        m_os.close();
    }
    
    /* ========================================================================
     *
     * Private methods
     */

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

log.debug("input to mac: " + Hex.b2s(input));

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
}