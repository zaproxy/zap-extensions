/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.addon.encoder.processors.predefined;

public class IllegalUTF8Encoder extends DefaultEncodeDecodeProcessor {

    private int bytes;

    public IllegalUTF8Encoder(int bytes) {
        this.bytes = bytes;
    }

    @Override
    protected String processInternal(String value) {
        return getIllegalUTF8Encode(value, bytes);
    }

    private String getIllegalUTF8Encode(String msg, int bytes) {
        char[] inputArray = msg.toCharArray();

        if (bytes != 4 && bytes != 3) {
            bytes = 2;
        }

        // numbers of characters * number of bytes * ("%" + Hex + Hex)
        StringBuilder sbResult = new StringBuilder(inputArray.length * bytes * 3);
        for (char c : inputArray) {

            if (bytes == 4) {
                sbResult.append('%').append(Integer.toHexString(0xff & ((byte) 0xf0)));
                sbResult.append('%').append(Integer.toHexString(0xff & ((byte) 0x80)));
                sbResult.append('%')
                        .append(Integer.toHexString(0xff & ((byte) (0x80 | ((c & 0x7f) >> 6)))));
                sbResult.append('%')
                        .append(Integer.toHexString(0xff & ((byte) (0x80 | (c & 0x3f)))));

            } else if (bytes == 3) {
                sbResult.append('%').append(Integer.toHexString(0xff & ((byte) 0xe0)));
                sbResult.append('%')
                        .append(Integer.toHexString(0xff & ((byte) (0x80 | ((c & 0x7f) >> 6)))));
                sbResult.append('%')
                        .append(Integer.toHexString(0xff & ((byte) (0x80 | (c & 0x3f)))));
            } else {
                sbResult.append('%')
                        .append(Integer.toHexString(0xff & ((byte) (0xc0 | ((c & 0x7f) >> 6)))));
                sbResult.append('%')
                        .append(Integer.toHexString(0xff & ((byte) (0x80 | (c & 0x3f)))));
            }
        }

        return sbResult.toString();
    }
}
