/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.tokengen;

import java.math.BigInteger;

public class TokenRandomStream implements com.fasteasytrade.JRandTest.IO.RandomStream {

    private CharacterFrequencyMap cfm = null;
    private int offset = 0;
    private int byteOffset = 0;
    private byte[] bytes = null;
    private boolean open = false;
    private String fileName = "TokenRandomStream";

    public TokenRandomStream(CharacterFrequencyMap cfm) {
        this.cfm = cfm;
        open = true;
    }

    @Override
    public boolean closeInputStream() {
        open = false;
        return true;
    }

    @Override
    public String getFilename() {
        return fileName;
    }

    @Override
    public boolean isOpen() {
        return open;
    }

    @Override
    public boolean openInputStream() throws Exception {
        offset = 0;
        open = true;
        readNextToken();
        return true;
    }

    private void readNextToken() throws Exception {
        bytes = cfm.getByteArrayToken(offset);
        if (bytes == null) {
            open = false;
        }
        offset++;
        byteOffset = 0;
    }

    private BigInteger readNumber(int sizeInBytes) throws Exception {
        byte[] ba = new byte[sizeInBytes];

        for (int i = 0; i < sizeInBytes; i++) {
            if (!open) {
                return BigInteger.valueOf(-1);
            }
            ba[i] = bytes[byteOffset];
            byteOffset++;
            if (byteOffset >= bytes.length) {
                readNextToken();
            }
        }
        return new BigInteger(ba);
    }

    @Override
    public byte readByte() throws Exception {
        return readNumber(1).byteValue();
    }

    @Override
    public int readInt() throws Exception {
        return readNumber(4).intValue();
    }

    @Override
    public long readLong() throws Exception {
        return readNumber(8).longValue();
    }

    @Override
    public void setFilename(String fileName) {
        this.fileName = fileName;
    }
}
