/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.testutils.PassiveScannerTestUtils;

abstract class PassiveScannerTest<T extends PluginPassiveScanner>
        extends PassiveScannerTestUtils<T> {

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionPscanRules());
    }

    /**
     * Returns a set of alert ref indices (1-based) to skip in the contiguity check.
     *
     * @return set of alert ref indices to skip, or empty set for no skips
     */
    protected Set<Integer> getSkippedAlertRefs() {
        return Set.of();
    }

    @Override
    public void shouldHaveExpectedAlertRefsInExampleAlerts() {
        Set<Integer> skipped = getSkippedAlertRefs();
        if (skipped.isEmpty()) {
            super.shouldHaveExpectedAlertRefsInExampleAlerts();
            return;
        }
        // Given / When
        @SuppressWarnings("unchecked")
        T rule = (T) getScanRule();
        List<String> alertRefs =
                rule.getExampleAlerts().stream().map(alert -> alert.getAlertRef()).toList();
        int pluginId = Integer.parseInt(alertRefs.get(0).split("-")[0]);
        // Then — build expected refs: 1..N skipping any in skipped set
        List<String> expected = new ArrayList<>();
        for (int i = 1; i <= alertRefs.size() + skipped.size(); i++) {
            if (!skipped.contains(i)) {
                expected.add(pluginId + "-" + i);
            }
        }
        MatcherAssert.assertThat(alertRefs, Matchers.equalTo(expected));
    }
}
