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

public class UnicodeEncoder extends DefaultEncodeDecodeProcessor {

    @Override
    protected String processInternal(String value) throws Exception {
        String str = value == null ? "" : value;
        String tmp;
        StringBuilder sb = new StringBuilder();
        char c;
        int i;
        int j;
        sb.setLength(0);
        for (i = 0; i < str.length(); i++) {
            c = str.charAt(i);
            sb.append("%u");
            j = (c >>> 8); // pop high 8 bits
            tmp = Integer.toHexString(j);
            if (tmp.length() == 1) sb.append('0');
            sb.append(tmp);
            j = (c & 0xFF); // pop low 8 bits
            tmp = Integer.toHexString(j);
            if (tmp.length() == 1) sb.append('0');
            sb.append(tmp);
        }
        return (sb.toString());
    }
}
