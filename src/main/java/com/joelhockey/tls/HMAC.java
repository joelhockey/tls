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

import java.security.*;

/**
 * Perfroms the HMAC as defined by RFC 2104
 *
 *	@author		Joel Hockey
 */
public class HMAC {

    private byte[] m_k_ipad = new byte[64];
    private byte[] m_k_opad = new byte[64];
    MessageDigest m_md = null;

    /**
     * Class constructor specifying the MessageDigest and secret to use
     *
     * @param md        the MessageDigest (MD5 or SHA1).
     * @param secret    the secret to seed the md.
     */
    public HMAC(MessageDigest md, byte[] key) {
        setMD(md);
        setKey(key);
    }

    /* ========================================================================
     *
     * Methods
     */

    /** Set the MessageDigest for HMAC
     *
     * @param md    the MessageDigest
     */
    public void setMD(MessageDigest md) {
        m_md = md;
    }

    /**
     * Set the secret key for HMAC
     *
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
        byte[] tempKey = keyLength > 64 ? m_md.digest(key) : key;

        // get m_k_ipad and m_k_opad
        for (int i = 0; i < keyLength; i++) {
            m_k_ipad[i] = (byte) (0x36 ^ tempKey[i]);
            m_k_opad[i] = (byte) (0x5C ^ tempKey[i]);
        }

        for (int i = keyLength; i < 64; i++) {
            m_k_ipad[i] = 0x36;
            m_k_opad[i] = 0x5C;
        }
    }

    /**
     * Digest the HMAC
     *
     * @param input the byte array input
     *
     * @return byte[] the HMAC value
     */
    public byte[] digest(byte[] input) {

        m_md.reset();
        m_md.update(m_k_ipad);
        m_md.update(input);
        byte[] inner = m_md.digest();
        m_md.update(m_k_opad);
        m_md.update(inner);
        return m_md.digest();
    }
}