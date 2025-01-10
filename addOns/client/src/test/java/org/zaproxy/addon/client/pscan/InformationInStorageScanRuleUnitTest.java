/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.client.pscan;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.Base64;
import java.util.List;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ReportedEvent;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link InformationInStorageScanRule}. */
class InformationInStorageScanRuleUnitTest extends TestUtils {

    private InformationInStorageScanRule rule;
    private ClientPassiveScanHelper helper;

    @BeforeEach
    void setUp() {
        rule = new InformationInStorageScanRule();
        mockMessages(new ExtensionClientIntegration());
        helper = mock(ClientPassiveScanHelper.class);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSetEnabled(boolean enabled) {
        // Given
        rule.setEnabled(!enabled);
        // When
        rule.setEnabled(enabled);
        // Then
        assertThat(rule.isEnabled(), is(enabled));
    }

    @Test
    void shouldReturnTheRightDefaults() {
        // Given / When
        List<Alert> exList = rule.getExampleAlerts();
        // Then
        assertThat(rule.isEnabled(), is(true));
        assertThat(rule.getId(), is(120000));
        assertThat(rule.getName(), is("Information Disclosure - Information in Browser Storage"));
        assertThat(
                rule.getHelpLink(),
                is(
                        "https://www.zaproxy.org/docs/desktop/addons/client-side-integration/pscan/#id-120000"));
        assertThat(exList.size(), is(2));
        assertThat(
                exList.get(0).getName(),
                is("Information Disclosure - Information in Browser localStorage"));
        assertThat(exList.get(0).getParam(), is("key"));
        assertThat(exList.get(0).getPluginId(), is(120000));
        assertThat(exList.get(0).getAlertRef(), is("120000-1"));
        assertThat(exList.get(0).getConfidence(), is(3));
        assertThat(exList.get(0).getRisk(), is(0));
        assertThat(exList.get(0).getCweId(), is(359));
        assertThat(exList.get(0).getWascId(), is(13));
        assertThat(
                exList.get(1).getName(),
                is("Information Disclosure - Information in Browser sessionStorage"));
        assertThat(exList.get(1).getParam(), is("key"));
        assertThat(exList.get(1).getPluginId(), is(120000));
        assertThat(exList.get(1).getAlertRef(), is("120000-2"));
        assertThat(exList.get(1).getConfidence(), is(3));
        assertThat(exList.get(1).getRisk(), is(0));
        assertThat(exList.get(1).getCweId(), is(359));
        assertThat(exList.get(1).getWascId(), is(13));
    }

    @ParameterizedTest
    @ValueSource(strings = {"localStorage", "sessionStorage"})
    void shouldRaiseAlertsForStorageEvents(String type) {
        // Given
        ReportedEvent event = getReportedEvent(type, "test");
        // When
        rule.scanReportedObject(event, helper);
        // Then
        verify(helper).raiseAlert(any(), any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"localStorage", "sessionStorage"})
    void shouldRaiseAlertsWithDecodedValueForStorageEvents(String type) {
        // Given
        String value = "this_is_a_test_string";
        ReportedEvent event =
                getReportedEvent(type, Base64.getEncoder().encodeToString(value.getBytes()));
        ArgumentCaptor<Alert> captor = ArgumentCaptor.forClass(Alert.class);
        // When
        rule.scanReportedObject(event, helper);
        // Then
        verify(helper).raiseAlert(captor.capture(), any());
        Alert alert = captor.getValue();
        assertThat(alert, is(notNullValue()));
        assertThat(alert.getOtherInfo(), containsString(value));
    }

    @ParameterizedTest
    @ValueSource(strings = {"cookies", "domMutation", ""})
    void shouldNotRaiseAlertsForNonStorageEvents(String type) {
        // Given
        ReportedEvent event = getReportedEvent(type, "any");
        // When
        rule.scanReportedObject(event, helper);
        // Then
        verify(helper, times(0)).raiseAlert(any(), any());
    }

    private static ReportedEvent getReportedEvent(String eventName, String value) {
        return new ReportedEvent(
                JSONObject.fromObject(
                        "{eventName='"
                                + eventName
                                + "', id='key', text='"
                                + value
                                + "', timestamp=1, count=0}"));
    }
}
