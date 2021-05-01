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

import java.util.function.Consumer;

public class HexStringEncoder extends DefaultEncodeDecodeProcessor {

    @Override
    protected String processInternal(String value) {
        return getHexString(value.getBytes());
    }

    protected static String getHexString(byte[] buf) {
        return getHexString(buf, sb -> {});
    }

    private static String getHexString(byte[] buf, Consumer<StringBuilder> pre) {
        StringBuilder sb = new StringBuilder(20);
        for (int i = 0; i < buf.length; i++) {
            pre.accept(sb);
            int digit = buf[i] & 0xFF;
            String hexDigit = Integer.toHexString(digit).toUpperCase();
            if (hexDigit.length() == 1) {
                sb.append('0');
            }
            sb.append(hexDigit);
        }
        return sb.toString();
    }

    static String getPercentHexString(byte[] buf) {
        return getHexString(buf, sb -> sb.append('%'));
    }
}
