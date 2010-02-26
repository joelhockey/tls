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

/**
 * Does Hex
 *
 *  @author Joel Hockey
 */
public class Hex {

    public static final char[] MAP = "0123456789abcdef".toCharArray();

    public static String b2s(byte[] buf) { return b2s(buf, 0, buf.length); }

    public static String b2s(byte[] buf, int offset, int len) {
        char[] ch = new char[len * 2];
        int j = 0;

        for (int i = offset; i < offset + len; i++) {
            ch[j++] = MAP[(buf[i] & 0xff) >> 4];
            ch[j++] = MAP[buf[i] & 0xf];
        }
        return new String(ch);
    }
}