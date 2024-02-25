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
package org.zaproxy.addon.commonlib.scanrules;

import org.parosproxy.paros.core.scanner.Alert;

public enum Risk {
    INFO(Alert.RISK_INFO),
    LOW(Alert.RISK_LOW),
    MEDIUM(Alert.RISK_MEDIUM),
    HIGH(Alert.RISK_HIGH);

    private final int value;

    Risk(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
