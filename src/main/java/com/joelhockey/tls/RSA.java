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

import java.math.BigInteger;
import java.util.Random;

/**
 * Does RSA encryption
 *  @author Joel Hockey
 */
public class RSA {

    // Instance variables
    private byte[] certs;
    private int certsOffset;

    private BigInteger modulus;
    private BigInteger exponent;
    private int keysize;

    private Random random;

    public RSA() {
        random = new Random();
    }

    /**
     *
     * Certificate  ::=  SEQUENCE  {
     *      tbsCertificate       TBSCertificate,
     *      signatureAlgorithm   AlgorithmIdentifier,
     *      signatureValue       BIT STRING  }
     *
     *  TBSCertificate  ::=  SEQUENCE  {
     *      version         [0]  EXPLICIT Version DEFAULT v1,
     *      serialNumber         CertificateSerialNumber,
     *      signature            AlgorithmIdentifier,
     *      issuer               Name,
     *      validity             Validity,
     *      subject              Name,
     *      subjectPublicKeyInfo SubjectPublicKeyInfo,
     *      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                           -- If present, version shall be v2 or v3
     *      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                           -- If present, version shall be v2 or v3
     *      extensions      [3]  EXPLICIT Extensions OPTIONAL
     *                           -- If present, version shall be v3
     *      }
     *
     * SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *      algorithm            AlgorithmIdentifier,
     *      subjectPublicKey     BIT STRING  }
     *
     * RSAPublicKey ::= SEQUENCE {
     *      modulus INTEGER
     *      publicExponent INTEGER }
     */
    public void setCertificates(byte[] buf, int offset , int len) {
        certs = buf;
        certsOffset = offset;
        int asnlen = 0;

        // Certificate, TBSCertificate
        for (int i = 0; i < 2; i++) {
            certsOffset++;
            asnlen = readLengthFromBuf();
        }

        // check for version
        if ((buf[certsOffset] & 0x80) > 0) {
            certsOffset++;
            certsOffset++;
            asnlen = readLengthFromBuf();
            certsOffset += asnlen;
        }

        // TBSCertificate - serialNumber, signature, issuer, validity, subject
        for (int i = 0; i < 5; i++) {
            certsOffset++;
            asnlen = readLengthFromBuf();
            certsOffset += asnlen;
        }

        // TBSCertificate - SubjectPublicKeyInfo
        certsOffset++;
        asnlen = readLengthFromBuf();
        // TBSCertificate - SubjectPublicKeyInfo - algorithm
        certsOffset++;
        asnlen = readLengthFromBuf();
        certsOffset += asnlen;

        // TBSCertificate - SubjectPublicKeyInfo - BitString
        certsOffset++;
        asnlen = readLengthFromBuf();

        // TBSCertificate - SubjectPublicKeyInfo - BitString - RSAPublicKey
        certsOffset++;
        certsOffset++;
        asnlen = readLengthFromBuf();

        // TBSCertificate - SubjectPublicKeyInfo - RSAPublicKey - modulus
        certsOffset++;
        int modLen = readLengthFromBuf();
        byte[] mod = new byte[modLen];
        System.arraycopy(certs, certsOffset, mod, 0, modLen);
        certsOffset+= modLen;
        modulus = new BigInteger(1, mod);
        int i = 0;
        keysize = modLen;
        while (mod[i++] == 0) {
            keysize--;
        }

        // TBSCertificate - SubjectPublicKeyInfo - RSAPublicKey - exponent
        certsOffset++;
        int expLen = readLengthFromBuf();
        byte[] exp = new byte[expLen];
        System.arraycopy(certs, certsOffset, exp, 0, expLen);
        certsOffset+= expLen;
        exponent = new BigInteger(1, exp);
    }

    public byte[] encrypt(byte[] in) {
        // pkcs1 padding
        byte[] temp = new byte[keysize - 1];
        for (int i = 0; i < temp.length; i++) {
            // make sure there are no bytes with value 0
            temp[i] = (byte) (random.nextInt(255) + 1);
        }
        temp[0] = 0x02;
        temp[temp.length - in.length - 1] = 0x00;

        System.arraycopy(in, 0, temp, temp.length - in.length, in.length);

        BigInteger bi = new BigInteger(1, temp);
        BigInteger retval = bi.modPow(exponent, modulus);
        byte[] out = retval.toByteArray();

        // chop off extra zero from front if needed
        if (out.length > keysize) {
            byte[] b = new byte[keysize];
            System.arraycopy(out, out.length - keysize, b, 0, keysize);
            return b;
        } else {
            return out;
        }
    }

    private int readLengthFromBuf() {
        int len = certs[certsOffset++] & 0xff;
        if (len < 128) {
            return len;
        } else {
            len %= 128;
            int retval = 0;
            for (int i = 0; i < len; i++) {
                retval <<= 8;
                retval += certs[certsOffset++] & 0xff;
            }
            return retval;
        }
    }
}