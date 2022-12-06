/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.reports.sarif;

import java.util.Locale;
import org.parosproxy.paros.core.scanner.Alert;

/**
 * Sarif level property enumeration. See
 * https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317648
 *
 * @author albert
 */
public enum SarifLevel {

    /*
     * The rule specified by ruleId was evaluated and a serious problem was found.
     */
    ERROR(Alert.RISK_HIGH),

    /* The rule specified by ruleId was evaluated and a problem was found. */
    WARNING(Alert.RISK_MEDIUM),

    /*
     * The rule specified by ruleId was evaluated and a minor problem or an
     * opportunity to improve the code was found.
     */
    NOTE(Alert.RISK_LOW),

    /*
     * The concept of “severity” does not apply to this result because the kind
     * property (§3.27.9) has a value other than "fail".
     */
    NONE(Alert.RISK_INFO),
    ;

    private int alertRisk;

    SarifLevel(int alertRisk) {
        this.alertRisk = alertRisk;
    }

    public static SarifLevel fromAlertRisk(int alertRisk) {
        for (SarifLevel level : values()) {
            if (level.alertRisk == alertRisk) {
                return level;
            }
        }
        throw new IllegalArgumentException("Unsupported alert risk value:" + alertRisk);
    }

    public int getAlertRisk() {
        return alertRisk;
    }

    /**
     * Converts to level value inside Sarif JSON reports
     *
     * @return level value (e.g. "error") - always lower cased (as defined by SARIF spec)
     */
    public String getValue() {
        return name().toLowerCase(Locale.ROOT);
    }
}
