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

import java.util.Objects;

/**
 * Identifies a scan tool with a stable id and an i18n display name.
 *
 * @since 1.39.0
 */
public record GspmTool(String id, String displayName) {
    public GspmTool {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(displayName, "displayName must not be null");
    }
}
