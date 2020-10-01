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
package org.zaproxy.zap.testutils;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.isEmptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import net.htmlparser.jericho.Source;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.pscan.PassiveScanData;
import org.zaproxy.zap.extension.pscan.PassiveScanTestHelper;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PassiveScanner;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Class with utility/helper methods for passive scanner tests ({@link
 * org.zaproxy.zap.extension.pscan.PluginPassiveScanner PluginPassiveScanner}).
 *
 * @param <T> the type of the passive scanner.
 */
public abstract class PassiveScannerTestUtils<T extends PassiveScanner> extends TestUtils {

    protected T rule;
    protected PassiveScanThread parent;
    protected PassiveScanData passiveScanData = mock(PassiveScanData.class);
    protected List<Alert> alertsRaised;

    public PassiveScannerTestUtils() {
        super();
    }

    @BeforeEach
    public void setUp() throws Exception {
        setUpZap();

        alertsRaised = new ArrayList<>();
        parent =
                new PassiveScanThread(null, null, new ExtensionAlert(), null) {
                    @Override
                    public void raiseAlert(int id, Alert alert) {
                        defaultAssertions(alert);
                        alertsRaised.add(alert);
                    }
                };
        rule = createScanner();
        rule.setParent(parent);
    }

    protected void defaultAssertions(Alert alert) {
        if (rule instanceof PluginPassiveScanner) {
            PluginPassiveScanner pps = (PluginPassiveScanner) rule;
            assertThat(
                    "PluginPassiveScanner rules should set its ID to the alert.",
                    alert.getPluginId(),
                    is(equalTo(pps.getPluginId())));
        }
        assertThat(
                "Passive rules should not raise alerts with attack field.",
                alert.getAttack(),
                isEmptyOrNullString());
    }

    protected abstract T createScanner();

    protected void scanHttpRequestSend(HttpMessage msg) {
        initRule(msg);
        rule.scanHttpRequestSend(msg, -1);
    }

    protected void scanHttpResponseReceive(HttpMessage msg) {
        initRule(msg);
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
    }

    private void initRule(HttpMessage msg) {
        if (rule instanceof PluginPassiveScanner) {
            PassiveScanTestHelper.init((PluginPassiveScanner) rule, parent, msg, passiveScanData);
        }
    }

    protected Source createSource(HttpMessage msg) {
        return new Source(msg.getResponseBody().toString());
    }

    @TestFactory
    Collection<DynamicTest> commonScanRuleTests() {
        List<DynamicTest> commonTests = new ArrayList<>();
        if (rule instanceof PluginPassiveScanner) {
            commonTests.add(testScanRuleHasName());
        }
        return commonTests;
    }

    private DynamicTest testScanRuleHasName() {
        return dynamicTest(
                "shouldHaveI18nNonEmptyName",
                () -> {
                    setUp();
                    shouldHaveI18nNonEmptyName();
                });
    }

    private void shouldHaveI18nNonEmptyName() {
        // Given / When
        String name = rule.getName();
        // Then
        assertThat(name, not(isEmptyOrNullString()));
        assertThat(
                "Name does not seem to be i18n'ed, not found in the resource bundle: " + name,
                extensionResourceBundle.keySet().stream()
                        .map(extensionResourceBundle::getString)
                        .anyMatch(str -> str.equals(name)));
    }
}
