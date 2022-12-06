/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.reports.sarif;

import java.util.Base64;

public class SarifBase64Encoder {

    public static final SarifBase64Encoder DEFAULT = new SarifBase64Encoder();

    public String encodeBytesToBase64(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        byte[] encoded = Base64.getEncoder().encode(bytes);
        return new String(encoded);
    }
}
