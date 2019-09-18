/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.analyzer.structural;

/** Base on {@link org.parosproxy.paros.core.scanner.NameValuePair} */
public class SimpleNameValuePair implements WebSocketNameValuePair {

    public static final String OBJECT_NAME = "obj";
    public static final String ARRAY_NAME = "arr";
    public static final String VAR_NAME = "var";

    private String name;
    private String value;
    private Type type;
    private int position;

    private SimpleNameValuePair(String name, String value, Type type, int position) {
        this.name = name;
        this.value = value;
        this.type = type;
        this.position = position;
    }

    /** @return Returns the name. */
    @Override
    public String getName() {
        return name;
    }

    /** @return Returns the value. */
    @Override
    public String getValue() {
        return value;
    }

    /** @return Returns the position. */
    @Override
    public int getPosition() {
        return position;
    }

    @Override
    public void setValue(String value) {
        this.value = value;
    }

    @Override
    public Type getType() {
        return type;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + position;
        result = prime * result + ((value == null) ? 0 : value.hashCode());
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        return result;
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
        SimpleNameValuePair other = (SimpleNameValuePair) obj;

        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        if (position != other.position) {
            return false;
        }
        if (type == null) {
            if (other.type != null) {
                return false;
            }
        } else if (!type.equals(other.type)) {
            return false;
        }
        if (value == null) {
            if (other.value != null) {
                return false;
            }
        } else if (!value.equals(other.value)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        StringBuilder strBuilder = new StringBuilder(75);
        strBuilder.append("[Position=").append(position);
        if (name != null) {
            strBuilder.append(", Name=").append(name);
        }
        if (value != null) {
            strBuilder.append(", Value=").append(value);
        }
        if (type != null) {
            strBuilder.append(", Type=").append(type);
        }
        strBuilder.append(']');
        return strBuilder.toString();
    }

    public static class Builder {

        private String name = null;
        private int position;
        private String value = null;
        private Type type = Type.UNDEFINED;

        public Builder(WebSocketNameValuePair nameValuePair) {
            this.name = nameValuePair.getName();
            this.position = nameValuePair.getPosition();
            this.value = nameValuePair.getValue();
            this.type = nameValuePair.getType();
        }

        public Builder() {}

        /** Wraps name up into "special" characters like the following one {\@name} */
        public Builder setNameWithMeta(String name) {
            this.name = "{@" + name + "}";

            return this;
        }
        /** @param name The name to set. */
        public Builder setName(String name) {
            this.name = name;
            return this;
        }

        /** @param position The position to set. */
        public Builder setPosition(int position) {
            this.position = position;
            return this;
        }

        public Builder setType(Type type) {
            this.type = type;
            return this;
        }

        public Builder setValue(Double value) {
            this.value = Double.toString(value);
            this.type = Type.DOUBLE;
            return this;
        }

        public Builder setValue(Boolean value) {
            this.value = Boolean.toString(value);
            this.type = Type.BOOLEAN;
            return this;
        }

        public Builder setValue(Integer value) {
            this.value = Integer.toString(value);
            this.type = Type.INTEGER;
            return this;
        }

        public Builder setValue(String value) {
            this.value = value;
            this.type = Type.TEXT;
            return this;
        }

        public Builder setValue(String value, Type type) {
            this.value = value;
            this.type = type;
            return this;
        }

        public String getName() {
            return name;
        }

        public int getPosition() {
            return position;
        }

        public Object getValue() {
            return value;
        }

        public Type getType() {
            return type;
        }

        public Builder clear() {
            name = null;
            type = Type.UNDEFINED;
            value = null;
            position = 0;
            return this;
        }

        public SimpleNameValuePair build() {
            SimpleNameValuePair nameValuePair =
                    new SimpleNameValuePair(name, value, type, position);
            clear();
            return nameValuePair;
        }
    }
}
