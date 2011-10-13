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

import java.io.IOException;
import java.io.OutputStream;

/**
 * OutputStream for TLSSocket
 *	@author		Joel Hockey
 */
public class TLSOutputStream extends OutputStream {

    // Instance variables
    private TLSSocket tls;
    public TLSOutputStream(TLSSocket tls) {
        this.tls = tls;
    }

    public void write(int i) throws IOException {
        write(new byte[]{(byte)i}, 0, 1);
    }

    public void write(byte[] msg, int offset, int len) throws IOException {
        // check for any alerts or other messages that may have arrived
        tls.readAvailable();

        if (!tls.connected()) {
            tls.connect();
        }
        tls.getRecord().sendMessage(Record.CONTENTTYPE_APPLICATION_DATA, msg);
    }
}