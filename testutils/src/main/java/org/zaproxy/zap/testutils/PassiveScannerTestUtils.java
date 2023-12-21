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
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import net.htmlparser.jericho.Source;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.alert.ExampleAlertProvider;
import org.zaproxy.zap.extension.pscan.PassiveScanData;
import org.zaproxy.zap.extension.pscan.PassiveScanTaskHelper;
import org.zaproxy.zap.extension.pscan.PassiveScanner;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Class with utility/helper methods for passive scanner tests ({@link
 * org.zaproxy.zap.extension.pscan.PluginPassiveScanner PluginPassiveScanner}).
 *
 * @param <T> the type of the passive scanner.
 */
public abstract class PassiveScannerTestUtils<T extends PassiveScanner> extends TestUtils
        implements ScanRuleTests {

    protected T rule;
    protected PassiveScanTaskHelper helper;
    protected PassiveScanData passiveScanData;
    protected List<Alert> alertsRaised;

    @BeforeEach
    public void setUp() throws Exception {
        setUpZap();

        passiveScanData =
                mock(PassiveScanData.class, withSettings().strictness(Strictness.LENIENT));
        alertsRaised = new ArrayList<>();
        helper = mock(PassiveScanTaskHelper.class, withSettings().strictness(Strictness.LENIENT));
        doAnswer(
                        invocation -> {
                            Alert alert = invocation.getArgument(1);

                            defaultAssertions(alert);
                            alertsRaised.add(alert);
                            return null;
                        })
                .when(helper)
                .raiseAlert(any(), any());

        rule = createScanner();
        rule.setTaskHelper(helper);

        if (rule instanceof PluginPassiveScanner) {
            ((PluginPassiveScanner) rule).setHelper(passiveScanData);
        }
    }

    @Override
    public Object getScanRule() {
        return rule;
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
                is(emptyOrNullString()));
    }

    protected abstract T createScanner();

    protected void scanHttpRequestSend(HttpMessage msg) {
        init(msg);
        rule.scanHttpRequestSend(msg, -1);
    }

    private void init(HttpMessage msg) {
        msg.setHistoryRef(mock(HistoryReference.class));
        given(passiveScanData.getMessage()).willReturn(msg);
    }

    protected void scanHttpResponseReceive(HttpMessage msg) {
        init(msg);
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
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
        if (rule instanceof ExampleAlertProvider) {
            commonTests.add(testExampleAlerts());
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

    private DynamicTest testExampleAlerts() {
        return dynamicTest(
                "shouldHaveExampleAlerts",
                () -> {
                    setUp();
                    shouldHaveExampleAlerts();
                });
    }

    private void shouldHaveI18nNonEmptyName() {
        // Given / When
        String name = rule.getName();
        // Then
        assertThat(name, is(not(emptyOrNullString())));
        assertThat(
                "Name does not seem to be i18n'ed, not found in the resource bundle: " + name,
                extensionResourceBundle.keySet().stream()
                        .map(extensionResourceBundle::getString)
                        .anyMatch(str -> str.equals(name)));
    }

    private void shouldHaveExampleAlerts() {
        // Given / When
        List<Alert> alerts = assertDoesNotThrow(((ExampleAlertProvider) rule)::getExampleAlerts);
        // Then
        if (alerts == null) {
            return;
        }
        assertThat(alerts, is(not(empty())));
        alerts.forEach(this::defaultAssertions);
    }
}
