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
 *	Implements the TLS pseudo-random function (PRF)
 *
 *	@author		Joel Hockey
 *	@version	$Revision: 1.1 $
 */
public class PRF {

    private MessageDigest m_md5 = null;
    private MessageDigest m_sha = null;
    private HMAC m_hmac = null;

    /**
     * Class constructor.
     */
    public PRF() throws TLSException {
        try {
            m_md5 = MessageDigest.getInstance("MD5");
            m_sha = MessageDigest.getInstance("SHA");
            m_hmac = new HMAC(null, null);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new TLSException("Error in PRF.  Could not create message digests: " + e.getMessage());
        }
    }

    /**
     * Generates the PRF of the given inputs
     *
     * @param secret
     * @param label
     * @param seed
     * @param length    The length of the output to generate.
     *
     * @return	PRF of inputs
     */
    public byte[] getBytes(byte[] secret, String label, byte[] seed, int length)
            throws TLSException {

        byte[] output = new byte[length];

        // split secret into S1 and S2
        int lenS1 = secret.length / 2 + secret.length % 2;

        byte[] S1 = new byte[lenS1];
        byte[] S2 = new byte[lenS1];

        System.arraycopy(secret, 0, S1, 0, lenS1);
        System.arraycopy(secret, secret.length - lenS1, S2, 0, lenS1);

        // get the seed as concatenation of label and seed
        byte[] labelAndSeed = new byte[label.length() + seed.length];
        System.arraycopy(label.getBytes(), 0, labelAndSeed, 0, label.length());
        System.arraycopy(seed, 0, labelAndSeed, label.length(), seed.length);

        byte[] md5Output = p_hash(m_md5, 16, S1, labelAndSeed, length);
        byte[] shaOutput = p_hash(m_sha, 20, S2, labelAndSeed, length);

        // XOR md5 and sha to get output
        for (int i = 0; i < length; i++) {
            output[i] = (byte) (md5Output[i] ^ shaOutput[i]);
        }

        return output;
    }

     /**
      * Perform the P_hash function
      *
      * @param md     The MessageDigest function to use
      * @param digestLength The length of output from the given digest
      * @param secret   The TLS secret
      * @param seed     The seed to use
      * @param length The desired length of the output.
      *
      * @return The P_hash of the inputs.
      */
    private byte[] p_hash(MessageDigest md, int digestLength, byte[] secret,
        byte[] seed, int length) throws TLSException {

        // set up our hmac
        m_hmac.setMD(md);
        m_hmac.setKey(secret);

        byte[] output = new byte[length];   // what we return
        int offset = 0;     // how much data we have created so far
        int toCopy = 0;     // the amount of data to copy from current HMAC

        byte[] A = seed;    // initialise A(0)

        // concatenation of A and seed
        byte[] A_seed = new byte[digestLength + seed.length];
        System.arraycopy(seed, 0, A_seed, digestLength, seed.length);

        byte[] tempBuf = null;

        // continually perform HMACs and concatenate until we have enough output
        while( offset < length ) {

            // calculate the A to use.
	        A = m_hmac.digest(A);

            // concatenate A and seed and perform HMAC
            System.arraycopy(A, 0, A_seed, 0, digestLength);
	        tempBuf = m_hmac.digest(A_seed);

            // work out how much needs to be copied and copy it
            toCopy = tempBuf.length < (length - offset) ? tempBuf.length : length - offset;
            System.arraycopy(tempBuf, 0, output, offset, toCopy);
            offset += toCopy;
       }
       return output;
    }
}