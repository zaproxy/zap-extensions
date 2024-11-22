/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.commonlib;

/**
 * Tags to be associated with standardized scan policies which will be distributed as an add-on.
 *
 * @since 1.29.0
 */
public enum PolicyTag {
    DEV_CICD,
    DEV_STD,
    DEV_FULL,
    QA_STD,
    QA_FULL,
    SEQUENCE,
    API;

    protected static final String PREFIX = "POLICY_";
    private final String tag;

    private PolicyTag() {
        this.tag = PREFIX + this.name();
    }

    public String getTag() {
        return this.tag;
    }
}
