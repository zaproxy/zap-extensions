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
package org.zaproxy.addon.sqliwip;

import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.zap.testutils.ActiveScannerTestUtils;

/**
 * Base class for the {@link SqlInjectionModularScanRule} tests (the rule itself and each of its
 * detection strategies), wiring up the rule under test and the message bundle.
 *
 * <p>SQL injection probing legitimately needs more requests per parameter than {@link
 * ActiveScannerTestUtils}'s generic guideline, so the recommended ceilings are raised.
 */
public abstract class AbstractSqlInjectionModularScanRuleTest
        extends ActiveScannerTestUtils<SqlInjectionModularScanRule> {

    @Override
    protected void setUpMessages() {
        mockMessages("org.zaproxy.addon.sqliwip.resources.Messages", "sqliwip");
    }

    @Override
    protected SqlInjectionModularScanRule createScanner() {
        return new SqlInjectionModularScanRule();
    }

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(AttackStrength strength) {
        int recommendMax = super.getRecommendMaxNumberMessagesPerParam(strength);
        switch (strength) {
            case LOW:
                return recommendMax + 1;
            case MEDIUM:
            default:
                return recommendMax + 14;
            case HIGH:
                return recommendMax + 25;
            case INSANE:
                return recommendMax + 7;
        }
    }
}
