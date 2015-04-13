/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.payloads;

public class DefaultStringPayload implements StringPayload {

    private String value;

    public DefaultStringPayload(String value) {
        setValue(value);
    }

    @Override
    public Class<String> getTypeArgument() {
        return String.class;
    }

    @Override
    public String getValue() {
        return value;
    }

    /**
     * {@inheritDoc}
     * 
     * @throws IllegalArgumentException if {@code value} is null.
     */
    @Override
    public void setValue(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Parameter value must not be null.");
        }
        this.value = value;
    }

    @Override
    public DefaultStringPayload copy() {
        return new DefaultStringPayload(value);
    }
}