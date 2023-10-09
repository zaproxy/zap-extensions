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
package org.zaproxy.zap.extension.selenium.internal.stealth;

import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

public class Evasion {
    private final String name;
    private final EvasionType type;
    private final String code;

    private final Collection<String> browsers;

    public Evasion(String name, EvasionType type, String code, Collection<String> browsers) {
        this.name = name;
        this.type = type;
        this.code = code;
        this.browsers = Objects.requireNonNullElse(browsers, Collections.emptyList());
    }

    public String getName() {
        return name;
    }

    public EvasionType getType() {
        return type;
    }

    public String getCode() {
        return code;
    }

    public Collection<String> getBrowsers() {
        return browsers;
    }

    @Override
    public String toString() {
        return "Evasion \"" + name + "\", " + type;
    }
}
