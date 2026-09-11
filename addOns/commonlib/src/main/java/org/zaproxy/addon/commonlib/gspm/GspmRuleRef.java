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
package org.zaproxy.addon.commonlib.gspm;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * A lightweight reference to a scan rule by its numeric id, used within a {@link GspmRuleSet}.
 *
 * <p>The {@code name} field is purely a human-readable comment and is not used for matching.
 *
 * @since 1.39.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GspmRuleRef {

    private int id;
    private String name; // comment only

    public GspmRuleRef() {}

    public GspmRuleRef(int id, String name) {
        this.id = id;
        this.name = name;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
