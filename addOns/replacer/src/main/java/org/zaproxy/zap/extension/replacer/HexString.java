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
package org.zaproxy.zap.extension.replacer;

import java.util.regex.Pattern;

class HexString {
    static String compile(String binaryRegex) {
        TransformString current = new TransformString(binaryRegex);
        StringBuilder sb = new StringBuilder();
        while (current.hasNext()) {
            if (current.isEscapedCharEscaped()) {
                sb.append(TransformString.ESCAPE_CHAR);
                current.moveBy(2);
            } else if (current.isValidHex()) {
                sb.append(new String(new byte[] {current.readHex()}));
                current.moveBy(4);
            } else {
                sb.append(current.currentChar());
                current.moveBy(1);
            }
        }
        return sb.toString();
    }

    private static class TransformString {
        static final Pattern HEX_VALUE = Pattern.compile("^\\\\x\\p{XDigit}{2}.*");
        static final char ESCAPE_CHAR = '\\';
        static final String ESCAPED_ESCAPE_CHAR = "\\\\";

        private final String content;
        private int position;

        private TransformString(String content) {
            this.content = content;
            this.position = 0;
        }

        boolean isEscapedCharEscaped() {
            return content.substring(position).startsWith(ESCAPED_ESCAPE_CHAR);
        }

        boolean isValidHex() {
            return HEX_VALUE.matcher(content.substring(position)).matches();
        }

        byte readHex() {
            String value = "" + content.charAt(position + 2) + content.charAt(position + 3);
            return (byte) Integer.parseInt(value, 16);
        }

        char currentChar() {
            return content.charAt(position);
        }

        void moveBy(int numberOfCharsRead) {
            position += numberOfCharsRead;
        }

        boolean hasNext() {
            return position < content.length();
        }
    }
}
