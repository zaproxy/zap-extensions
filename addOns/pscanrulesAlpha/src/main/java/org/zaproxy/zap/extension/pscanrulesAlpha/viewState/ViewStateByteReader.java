/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesAlpha.viewState;

import java.nio.ByteBuffer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ViewStateByteReader {

    public static final Pattern CHARS_TO_ENCODE_IN_XML_PATTERN =
            Pattern.compile("[<>&]+", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    /** a pattern to use when looking at the output to check if a ViewState is protected by a MAC */
    public static final Pattern PATTERN_NO_HMAC =
            Pattern.compile(
                    "^\\s*<hmac>false</hmac>\\s*$", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    /**
     * read a sequence of n bytes from the ByteBuffer and return it as a byte array
     *
     * @param bb the ByteBuffer from which to read n bytes
     * @param n the number of bytes to read
     * @return a byte array containing the read data
     */
    public static byte[] readBytes(ByteBuffer bb, int n) {
        byte[] bytes = new byte[n];
        bb.get(bytes);
        return bytes;
    }

    /**
     * reads a NULL terminated String from the ByteBuffer
     *
     * @param bb the ByteBuffer containing the data to read
     * @return a String (not including the NULL byte)
     */
    public static String readNullTerminatedString(ByteBuffer bb) {
        StringBuffer sb = new StringBuffer();
        byte b = bb.get();
        while (b != 0x00) {
            sb.append((char) b);
            b = bb.get();
        }
        return new String(sb);
    }

    /**
     * gets a Little Endian Base 128 number from the Byte Buffer. This is a form of variable length
     * encoded int value.
     *
     * @param bb the ByteBuffer containing the data
     * @return an integer value
     */
    public static int readLittleEndianBase128Number(ByteBuffer bb) {
        int i;

        int tempBytesRead = 0;
        byte b = bb.get();
        tempBytesRead++;
        // get the lower 7 bits of b into i
        i = b & 0x7F;
        while ((b & 0x80) > 0) {
            // while the top bit of b is set (the "more" bit)
            // get another byte
            b = bb.get();
            tempBytesRead++;
            // left shift the lower 7 bits of b onto the left of the bits of data we have already
            // placed in i
            // i = ((i+1) <<7) | (b& 0x7F);
            i = ((b & 0x7F) << (7 * (tempBytesRead - 1))) | i;
        }
        return i;
    }

    public static String escapeString(String s) {
        String str = "";
        Matcher matcher = CHARS_TO_ENCODE_IN_XML_PATTERN.matcher(s);
        boolean malicious = matcher.find();
        if (malicious) str += "<![CDATA[";
        str += s;
        if (malicious) str += "]]>";
        return str;
    }

    public static Matcher hasNoHMac(String viewStateXml) {
        return PATTERN_NO_HMAC.matcher(viewStateXml);
    }
}
