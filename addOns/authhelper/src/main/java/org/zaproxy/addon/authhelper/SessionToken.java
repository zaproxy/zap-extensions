/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.authhelper;

import java.util.Locale;
import java.util.Objects;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;

public class SessionToken implements Comparable<SessionToken> {

    public static final String COOKIE_SOURCE = "cookie";
    public static final String ENV_SOURCE = "env";
    public static final String HEADER_SOURCE = "header";
    public static final String JSON_SOURCE = "json";
    public static final String SCRIPT_SOURCE = "script";
    public static final String URL_SOURCE = "url";

    private static final String BEARER_PREFIX = "bearer";

    private final String source;
    private final String key;
    private String value;
    private String fullValue;

    public SessionToken(String source, String key, String value) {
        super();
        this.source = source;
        this.key = key;
        this.value = value;
        this.fullValue = value;
        if (HEADER_SOURCE.equals(source) && HttpFieldsNames.AUTHORIZATION.equalsIgnoreCase(key)) {
            int spaceIndex = fullValue.indexOf(" ");
            if (spaceIndex > 0 && fullValue.toLowerCase(Locale.ROOT).startsWith(BEARER_PREFIX)) {
                // Cope with "bearer " and "bearer: "
                this.value = fullValue.substring(spaceIndex + 1);
            }
        }
    }

    public String getSource() {
        return source;
    }

    public String getKey() {
        return key;
    }

    public String getValue() {
        return value;
    }

    public String getFullValue() {
        return fullValue;
    }

    public String getToken() {
        return source + ":" + key;
    }

    @Override
    public int hashCode() {
        return Objects.hash(key, source, value);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        SessionToken other = (SessionToken) obj;
        return Objects.equals(key, other.key)
                && Objects.equals(source, other.source)
                && Objects.equals(value, other.value);
    }

    @Override
    public int compareTo(SessionToken o) {
        int result = compareStrings(source, o.source);
        if (result != 0) {
            return result;
        }

        result = compareStrings(key, o.key);
        if (result != 0) {
            return result;
        }

        return compareStrings(value, value);
    }

    private static int compareStrings(String string, String otherString) {
        if (string == null) {
            if (otherString == null) {
                return 0;
            }
            return -1;
        } else if (otherString == null) {
            return 1;
        }
        return string.compareTo(otherString);
    }

    @Override
    public String toString() {
        return "Source: " + source + " key: " + key + " value: " + value;
    }
}
