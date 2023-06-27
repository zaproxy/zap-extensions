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
package org.zaproxy.addon.network.internal;

import java.util.Objects;
import java.util.regex.Pattern;
import org.zaproxy.zap.utils.EnableableInterface;

/** A global exclusion, to be ignored by proxies and tools. */
public class GlobalExclusion implements EnableableInterface {

    private String name;
    private String value;
    private boolean enabled;

    public GlobalExclusion() {
        enabled = true;
    }

    public GlobalExclusion(String name, String value, boolean enabled) {
        this.name = name;
        this.value = value;
        this.enabled = enabled;
    }

    public GlobalExclusion(GlobalExclusion other) {
        name = other.name;
        value = other.value;
        enabled = other.enabled;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, enabled, value);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GlobalExclusion)) {
            return false;
        }
        GlobalExclusion other = (GlobalExclusion) obj;
        return enabled == other.enabled
                && Objects.equals(name, other.name)
                && Objects.equals(value, other.value);
    }

    /**
     * Validates the given {@code value} to use as a pattern with global exclusions.
     *
     * @param value the value to validate.
     * @return {@code true} if the provided  {@code value} is a valid pattern, {@code false}
     *     otherwise.
     * @throws IllegalArgumentException if the given  {@code value} is an illegal pattern.
     */
    public static boolean validatePattern(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        Pattern.compile(value);
        return true;
    }
}
