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
import java.io.InputStream;

/**
 * Input Stream for TLS Socket
 *	@author		Joel Hockey
 */
public class TLSInputStream extends InputStream {

    private TLSSocket tls;
    private byte[] tlsbuf = new byte[4096];
    private int start = 0;
    private int end = 0;
    private int available = 0;

    public TLSInputStream(TLSSocket tls) {
        this.tls = tls;
    }

    public int read() throws IOException {
        int len = read(tlsbuf, start, 1);
        if (len == -1) {
            return -1;
        }
        return tlsbuf[start++] & 0xff;
    }

    public int read(byte[] buf, int offset, int len) throws IOException {
        // update any new data that has arrived
        check();

        if (available == 0) {
            return -1;
        }

        int retval = available < len ? available : len;
        System.arraycopy(tlsbuf, start, buf, offset, retval);
        start+= retval;
        available -= retval;
        return retval;
    }

    public int available() {
        return available;
    }

    protected void addBytes(byte[] in) {
        // check if we have enough room.
        if (available + in.length > tlsbuf.length) {
            byte[] temp = new byte[tlsbuf.length + (in.length << 1)];
            System.arraycopy(tlsbuf, start, temp, 0, available);
            tlsbuf = temp;
        }

        // check if in will fit at end
        if (end + in.length > tlsbuf.length) {
            byte[] temp = new byte[tlsbuf.length];
            System.arraycopy(tlsbuf, start, temp, 0, available);
            start = 0; end = available;
            tlsbuf = temp;
        }

        // copy to end
        System.arraycopy(in, 0, tlsbuf, end, in.length);
        end += in.length;
        available += in.length;
    }

    private void check() throws IOException {
        tls.readAvailable();

        if (available == 0) {
            // force a read
            tls.readBlock();
            // keep reading if we can
            tls.readAvailable();
        }
    }
}