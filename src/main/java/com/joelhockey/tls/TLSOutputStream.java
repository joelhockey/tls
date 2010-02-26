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
 * OutputStream for TLSSocket
 *
 *	@author		Joel Hockey
 */
public class TLSOutputStream extends OutputStream {

    // Instance variables
    private TLSSocket m_tls;
    public TLSOutputStream(TLSSocket tls) {
        m_tls = tls;
    }

    public void write(int i) throws IOException {
        write(new byte[]{(byte)i}, 0, 1);
    }

    public void write(byte[] msg, int offset, int len) throws IOException {
        // check for any alerts or other messages that may have arrived
        m_tls.readAvailable();

        if (!m_tls.connected()) {
            m_tls.connect();
        }
        m_tls.getRecord().sendMessage(Record.CONTENTTYPE_APPLICATION_DATA, msg);
    }
}