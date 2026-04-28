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
package org.zaproxy.addon.wstgmapper.model;

import org.parosproxy.paros.Constant;

/**
 * Enumerates the manual review states a tester can assign to a WSTG test.
 *
 * <p>The enum also bridges persisted names to localized UI labels so the rest of the add-on can
 * work with a stable internal representation.
 */
public enum WstgTestStatus {
    NOT_TESTED("wstgmapper.status.notTested"),
    PASSED("wstgmapper.status.passed"),
    FAILED("wstgmapper.status.failed"),
    MANUAL_ONLY("wstgmapper.status.manualOnly"),
    NOT_APPLICABLE("wstgmapper.status.notApplicable");

    private final String i18nKey;

    WstgTestStatus(String i18nKey) {
        this.i18nKey = i18nKey;
    }

    public String getLabel() {
        return Constant.messages.getString(i18nKey);
    }

    @Override
    public String toString() {
        return getLabel();
    }

    public static WstgTestStatus fromString(String value) {
        for (WstgTestStatus s : values()) {
            if (s.name().equalsIgnoreCase(value)) {
                return s;
            }
        }
        return NOT_TESTED;
    }
}
