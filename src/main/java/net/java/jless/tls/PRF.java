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
import java.security.NoSuchAlgorithmException;

/**
 *	Implements the TLS pseudo-random function (PRF)
 *	@author		Joel Hockey
 */
public class PRF {

    private MessageDigest md5 = null;
    private MessageDigest sha = null;
    private HMAC hmac = null;

    /**
     * Class constructor.
     */
    public PRF() throws TLSException {
        try {
            md5 = MessageDigest.getInstance("MD5");
            sha = MessageDigest.getInstance("SHA");
            hmac = new HMAC(null, null);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new TLSException("Error in PRF.  Could not create message digests: " + e.getMessage());
        }
    }

    /**
     * Generates the PRF of the given inputs
     * @param secret
     * @param label
     * @param seed
     * @param length    The length of the output to generate.
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

        byte[] md5Output = p_hash(md5, 16, S1, labelAndSeed, length);
        byte[] shaOutput = p_hash(sha, 20, S2, labelAndSeed, length);

        // XOR md5 and sha to get output
        for (int i = 0; i < length; i++) {
            output[i] = (byte) (md5Output[i] ^ shaOutput[i]);
        }

        return output;
    }

     /**
      * Perform the P_hash function
      * @param md     The MessageDigest function to use
      * @param digestLength The length of output from the given digest
      * @param secret   The TLS secret
      * @param seed     The seed to use
      * @param length The desired length of the output.
      * @return The P_hash of the inputs.
      */
    private byte[] p_hash(MessageDigest md, int digestLength, byte[] secret,
        byte[] seed, int length) throws TLSException {

        // set up our hmac
        hmac.setMD(md);
        hmac.setKey(secret);

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
	        A = hmac.digest(A);

            // concatenate A and seed and perform HMAC
            System.arraycopy(A, 0, A_seed, 0, digestLength);
	        tempBuf = hmac.digest(A_seed);

            // work out how much needs to be copied and copy it
            toCopy = tempBuf.length < (length - offset) ? tempBuf.length : length - offset;
            System.arraycopy(tempBuf, 0, output, offset, toCopy);
            offset += toCopy;
       }
       return output;
    }
}