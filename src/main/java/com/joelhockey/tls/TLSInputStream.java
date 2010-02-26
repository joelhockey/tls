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

import java.io.*;

/**
 * Input Stream for TLS Socket
 *
 *	@author		Joel Hockey
 *	@version	$Revision: 1.1 $
 */
public class TLSInputStream extends InputStream {

    // Instance variables
    private TLSSocket m_tls;
    private byte[] m_buf = new byte[4096];
    private int m_start = 0;
    private int m_end = 0;
    private int m_available = 0;

    public TLSInputStream(TLSSocket tls) {
        m_tls = tls;
    }

    public int read() throws IOException {
        int len = read(m_buf, m_start, 1);
        if (len == -1) {
            return -1;
        }
        return m_buf[m_start++] & 0xff;
    }

    public int read(byte[] buf, int offset, int len) throws IOException {
        // update any new data that has arrived
        check();

        if (m_available == 0) {
            return -1;
        }

        int retval = m_available < len ? m_available : len;
        System.arraycopy(m_buf, m_start, buf, offset, retval);
        m_start+= retval;
        m_available -= retval;
        return retval;
    }

    public int available() {
        return m_available;
    }

    protected void addBytes(byte[] in) {
        // check if we have enough room.
        if (m_available + in.length > m_buf.length) {
            byte[] temp = new byte[m_buf.length + (in.length << 1)];
            System.arraycopy(m_buf, m_start, temp, 0, m_available);
            m_buf = temp;
        }

        // check if in will fit at end
        if (m_end + in.length > m_buf.length) {
            byte[] temp = new byte[m_buf.length];
            System.arraycopy(m_buf, m_start, temp, 0, m_available);
            m_start = 0; m_end = m_available;
            m_buf = temp;
        }

        // copy to end
        System.arraycopy(in, 0, m_buf, m_end, in.length);
        m_end += in.length;
        m_available += in.length;
    }

    private void check() throws IOException {
        m_tls.readAvailable();

        if (m_available == 0) {
            // force a read
            m_tls.readBlock();
            // keep reading if we can
            m_tls.readAvailable();
        }
    }
}