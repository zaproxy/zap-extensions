/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.internal;

import java.util.Objects;
import org.zaproxy.zap.utils.EnableableInterface;

/** A name/value pair, as shown in the OAuth2 extra token parameters table. */
public class ExtraParam implements EnableableInterface {

    private String name;
    private String value;

    public ExtraParam(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public ExtraParam(ExtraParam other) {
        this(other.name, other.value);
    }

    public String getName() {
        return name;
    }

    public String getValue() {
        return value;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public void setEnabled(boolean enabled) {
        // Always enabled.
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, value);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ExtraParam other)) {
            return false;
        }
        return Objects.equals(name, other.name) && Objects.equals(value, other.value);
    }
}
