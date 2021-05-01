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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Duplicated from Replacer addon. */
class HexString {
    private static final Pattern HEX_VALUE = Pattern.compile("\\\\?\\\\x\\p{XDigit}{2}");
    private static final String ESCAPED_ESCAPE_CHAR = "\\\\";

    static String compile(String binaryRegex) {
        Matcher matcher = HEX_VALUE.matcher(binaryRegex);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            String value = matcher.group();
            if (!value.startsWith(ESCAPED_ESCAPE_CHAR)) {
                value = convertByte(value.substring(2));
            }
            matcher.appendReplacement(sb, value);
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    private static String convertByte(String value) {
        return Matcher.quoteReplacement(
                new String(
                        new byte[] {(byte) Integer.parseInt(value, 16)},
                        StandardCharsets.US_ASCII));
    }
}
