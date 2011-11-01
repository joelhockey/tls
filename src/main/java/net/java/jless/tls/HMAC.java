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

package net.java.jless.tls;

import java.security.MessageDigest;

/**
 * Performs HMAC as defined by RFC 2104
 *	@author		Joel Hockey
 */
public class HMAC {

    private byte[] k_ipad = new byte[64];
    private byte[] k_opad = new byte[64];
    MessageDigest md = null;

    /**
     * Class constructor specifying the MessageDigest and secret to use
     * @param md        the MessageDigest (MD5 or SHA1).
     * @param secret    the secret to seed the md.
     */
    public HMAC(MessageDigest md, byte[] key) {
        setMD(md);
        setKey(key);
    }

    /** Set the MessageDigest for HMAC
     * @param md    the MessageDigest
     */
    public void setMD(MessageDigest md) {
        this.md = md;
    }

    /**
     * Set the secret key for HMAC
     * @param key   the key.
     */
     public void setKey(byte[] key) {
        int keyLength = 0;

        // get keyLength.
        if (key == null) {
            keyLength = 0;
        } else {
            keyLength = key.length;
        }

        // if the key is longer than 64 bytes then hash it.
        byte[] tempKey = keyLength > 64 ? md.digest(key) : key;

        // get m_k_ipad and m_k_opad
        for (int i = 0; i < keyLength; i++) {
            k_ipad[i] = (byte) (0x36 ^ tempKey[i]);
            k_opad[i] = (byte) (0x5C ^ tempKey[i]);
        }

        for (int i = keyLength; i < 64; i++) {
            k_ipad[i] = 0x36;
            k_opad[i] = 0x5C;
        }
    }

    /**
     * Digest the HMAC
     * @param input the byte array input
     * @return HMAC value
     */
    public byte[] digest(byte[] input) {

        md.reset();
        md.update(k_ipad);
        md.update(input);
        byte[] inner = md.digest();
        md.update(k_opad);
        md.update(inner);
        return md.digest();
    }
}