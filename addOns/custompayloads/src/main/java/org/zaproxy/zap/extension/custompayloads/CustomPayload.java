/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.custompayloads;

import org.zaproxy.zap.utils.EnableableInterface;

public class CustomPayload implements EnableableInterface {

    private boolean enabled;
    private String category;
    private String payload;

    public CustomPayload(String category, String payload) {
        this(true, category, payload);
    }

    public CustomPayload(boolean enabled, String category, String payload) {
        this.enabled = enabled;
        this.category = category;
        this.payload = payload;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void setEnabled(boolean flag) {
        enabled = flag;
    }

    public String getCategory() {
        return category;
    }

    public String getPayload() {
        return payload;
    }

    public CustomPayload copy() {
        return new CustomPayload(enabled, category, payload);
    }
}
