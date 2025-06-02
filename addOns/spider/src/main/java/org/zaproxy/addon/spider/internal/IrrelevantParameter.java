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
package org.zaproxy.addon.spider.internal;

import java.util.regex.Pattern;
import org.zaproxy.zap.utils.Enableable;

public class IrrelevantParameter extends Enableable {

    private final Pattern pattern;
    private final String name;
    private final boolean regex;

    public IrrelevantParameter(Pattern pattern) {
        super(true);

        if (pattern == null) {
            throw new IllegalArgumentException("Parameter pattern must not be null.");
        }

        this.pattern = pattern;
        this.regex = true;
        this.name = null;
    }

    public IrrelevantParameter(String name) {
        super(true);

        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Parameter name must not be null or empty.");
        }

        this.name = name;
        this.regex = false;
        this.pattern = null;
    }

    public IrrelevantParameter(IrrelevantParameter other) {
        super(other.isEnabled());

        this.name = other.name;
        this.regex = other.regex;
        this.pattern = other.pattern;
    }

    public String getValue() {
        if (isRegex()) {
            return pattern.pattern();
        }

        return name;
    }

    public boolean isRegex() {
        return regex;
    }

    /**
     * Tells whether or not the given name is considered an irrelevant parameter.
     *
     * @param name the name that will be checked
     * @return {@code true} if the name is considered irrelevant, {@code false} otherwise.
     */
    public boolean test(String name) {
        if (pattern != null) {
            return pattern.matcher(name).matches();
        }

        return this.name.equals(name);
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((pattern == null) ? 0 : pattern.pattern().hashCode());
        return result;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (!super.equals(object)) {
            return false;
        }
        if (getClass() != object.getClass()) {
            return false;
        }
        IrrelevantParameter other = (IrrelevantParameter) object;
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        if (pattern == null) {
            if (other.pattern != null) {
                return false;
            }
        } else if (other.pattern == null || !pattern.pattern().equals(other.pattern.pattern())) {
            return false;
        }
        return true;
    }

    public static Pattern createPattern(String regex) {
        return Pattern.compile(regex);
    }
}
