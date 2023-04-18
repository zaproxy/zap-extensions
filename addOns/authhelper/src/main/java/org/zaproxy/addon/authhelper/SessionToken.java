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

public class SessionToken {

    public static final String ENV_TYPE = "env";
    public static final String HEADER_TYPE = "header";
    public static final String JSON_TYPE = "json";
    public static final String SCRIPT_TYPE = "script";
    public static final String URL_TYPE = "url";

    private final String type;
    private final String key;
    private final String value;

    public SessionToken(String type, String key, String value) {
        super();
        this.type = type;
        this.key = key;
        this.value = value;
    }

    public String getType() {
        return type;
    }

    public String getKey() {
        return key;
    }

    public String getValue() {
        return value;
    }

    public String getToken() {
        return type + ":" + key;
    }
}
