/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.formhandler;

import java.util.Locale;
import java.util.Objects;
import org.zaproxy.zap.utils.Enableable;

class FormHandlerParamField extends Enableable {

    private String name;
    private String value;
    private boolean regex;

    public FormHandlerParamField() {
        this("", "", false, false);
    }

    public FormHandlerParamField(String name) {
        this(name, "", true, false);
    }

    public FormHandlerParamField(String name, String value) {
        this(name, value, true, false);
    }

    public FormHandlerParamField(String name, String value, boolean enabled, boolean regex) {
        super(enabled);

        Objects.requireNonNull(name);
        Objects.requireNonNull(value);
        this.regex = regex; // Set regex prior to handling name
        this.name = handleName(name);
        this.value = value;
    }

    public FormHandlerParamField(FormHandlerParamField field) {
        this(field.name, field.value, field.isEnabled(), field.isRegex());
    }

    public String getName() {
        return name;
    }

    private String handleName(String name) {
        return regex ? name : name.toLowerCase(Locale.ROOT);
    }

    public void setName(String name) {
        this.name = handleName(name);
    }

    public boolean hasName(String fieldName) {
        if (isRegex()) {
            return name.equals(fieldName);
        }
        return name.equalsIgnoreCase(fieldName);
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public boolean isRegex() {
        return regex;
    }

    public void setRegex(boolean regex) {
        this.regex = regex;
    }

    @Override
    public String toString() {
        return this.getName()
                + " with value: "
                + this.getValue()
                + " enabled: "
                + this.isEnabled()
                + " regex: "
                + this.isRegex();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + name.hashCode();
        result = prime * result + value.hashCode();
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        FormHandlerParamField other = (FormHandlerParamField) obj;
        if (hasName(other.getName())) {
            return equalAttributes(other);
        }
        return false;
    }

    private boolean equalAttributes(FormHandlerParamField other) {
        return value.equals(other.value) && isRegex() == other.isRegex();
    }
}
