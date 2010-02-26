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

import java.math.*;
import java.util.*;

/**
 * Does RSA encryption
 *
 *  @author Joel Hockey
 */
public class RSA {

    // Instance variables
    private byte[] m_certs;
    private int m_offset;

    private BigInteger m_modulus;
    private BigInteger m_exponent;
    private int m_keysize;

    private Random m_random;

    public RSA() {
        m_random = new Random();
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
        m_certs = buf;
        m_offset = offset;
        int asnlen = 0;

        // Certificate, TBSCertificate
        for (int i = 0; i < 2; i++) {
            m_offset++;
            asnlen = readLengthFromBuf();
        }

        // check for version
        if ((buf[m_offset] & 0x80) > 0) {
            m_offset++;
            m_offset++;
            asnlen = readLengthFromBuf();
            m_offset += asnlen;
        }

        // TBSCertificate - serialNumber, signature, issuer, validity, subject
        for (int i = 0; i < 5; i++) {
            m_offset++;
            asnlen = readLengthFromBuf();
            m_offset += asnlen;
        }

        // TBSCertificate - SubjectPublicKeyInfo
        m_offset++;
        asnlen = readLengthFromBuf();
        // TBSCertificate - SubjectPublicKeyInfo - algorithm
        m_offset++;
        asnlen = readLengthFromBuf();
        m_offset += asnlen;

        // TBSCertificate - SubjectPublicKeyInfo - BitString
        m_offset++;
        asnlen = readLengthFromBuf();

        // TBSCertificate - SubjectPublicKeyInfo - BitString - RSAPublicKey
        m_offset++;
        m_offset++;
        asnlen = readLengthFromBuf();

        // TBSCertificate - SubjectPublicKeyInfo - RSAPublicKey - modulus
        m_offset++;
        int modLen = readLengthFromBuf();
        byte[] mod = new byte[modLen];
        System.arraycopy(m_certs, m_offset, mod, 0, modLen);
        m_offset+= modLen;
        m_modulus = new BigInteger(1, mod);
        int i = 0;
        m_keysize = modLen;
        while (mod[i++] == 0) {
            m_keysize--;
        }

        // TBSCertificate - SubjectPublicKeyInfo - RSAPublicKey - exponent
        m_offset++;
        int expLen = readLengthFromBuf();
        byte[] exp = new byte[expLen];
        System.arraycopy(m_certs, m_offset, exp, 0, expLen);
        m_offset+= expLen;
        m_exponent = new BigInteger(1, exp);
    }

    public byte[] encrypt(byte[] in) {
        // pkcs1 padding
        byte[] temp = new byte[m_keysize - 1];
        for (int i = 0; i < temp.length; i++) {
            // make sure there are no bytes with value 0
            temp[i] = (byte) (m_random.nextInt(255) + 1);
        }
        temp[0] = 0x02;
        temp[temp.length - in.length - 1] = 0x00;

        System.arraycopy(in, 0, temp, temp.length - in.length, in.length);

        BigInteger bi = new BigInteger(1, temp);
        BigInteger retval = bi.modPow(m_exponent, m_modulus);
        byte[] out = retval.toByteArray();
        
        // chop off extra zero from front if needed
        if (out.length > m_keysize) {
            byte[] b = new byte[m_keysize];
            System.arraycopy(out, out.length - m_keysize, b, 0, m_keysize);
            return b;
        } else {
            return out;
        }
    }

    private int readLengthFromBuf() {
        int len = m_certs[m_offset++] & 0xff;
        if (len < 128) {
            return len;
        } else {
            len %= 128;
            int retval = 0;
            for (int i = 0; i < len; i++) {
                retval <<= 8;
                retval += m_certs[m_offset++] & 0xff;
            }
            return retval;
        }
    }
}