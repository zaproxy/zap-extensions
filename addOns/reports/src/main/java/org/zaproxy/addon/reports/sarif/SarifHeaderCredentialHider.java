/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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

import java.util.Locale;

/**
 * This class does hide credentials inside HTTP headers. When a credential is detected for a header,
 * the header value will replaced by a string containing only asterisks.
 */
public class SarifHeaderCredentialHider {

    static String CREDENTIAL_REPLACEMENT_ASTERISKS = "********";

    /**
     * Creates a safe header value. When a credential is detected for a supported header name, the
     * header value will replaced by string of a default length, containing only asterisks.
     *
     * @param headerName the name of the header
     * @param originHeaderValue the origin header value
     * @return origin header value or replacement string containing only asterisks
     */
    public String createSafeHeaderValue(String headerName, String originHeaderValue) {
        if (headerName == null) {
            return originHeaderValue;
        }

        if (originHeaderValue == null || originHeaderValue.isEmpty()) {
            return originHeaderValue;
        }

        String lowerCasedHeaderName = headerName.toLowerCase(Locale.ROOT);

        if (lowerCasedHeaderName.equals("authorization")) {
            return CREDENTIAL_REPLACEMENT_ASTERISKS;
        }

        return originHeaderValue;
    }
}
