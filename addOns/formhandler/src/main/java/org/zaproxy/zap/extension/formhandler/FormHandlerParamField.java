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
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((value == null) ? 0 : value.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!super.equals(obj)) return false;
        if (getClass() != obj.getClass()) return false;
        FormHandlerParamField other = (FormHandlerParamField) obj;
        if (name == null) {
            if (other.name != null) return false;
        } else if (!name.equals(other.name)) return false;
        if (value == null) {
            if (other.value != null) return false;
        } else if (!value.equals(other.value)) return false;
        return true;
    }
}
