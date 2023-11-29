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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.util.List;
import net.sf.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.ReportedEvent;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link JwtInStorageScanRule}. */
class JwtInStorageScanRuleUnitTest extends TestUtils {
    private static final String JWT_HEADER = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9";
    private static final String JWT_PAYLOAD =
            "eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MjIsInVzZXJuYW1lIjo"
                    + "iIiwiZW1haWwiOiJ0ZXN0QHRlc3QuY29tIiwicGFzc3dvcmQiOiJjYzAzZTc0N2E2YWZiYmNiZjhiZTc2NjhhY2ZlYmVlNSIsInJ"
                    + "vbGUiOiJjdXN0b21lciIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIwLjAuMC4wIiwicHJvZmlsZUltYWdlIjoiL2F"
                    + "zc2V0cy9wdWJsaWMvaW1hZ2VzL3VwbG9hZHMvZGVmYXVsdC5zdmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImN"
                    + "yZWF0ZWRBdCI6IjIwMjMtMTEtMjQgMTY6NDc6MjEuNTA4ICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjMtMTEtMjQgMTY6NDc6MjE"
                    + "uNTA4ICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTcwMDg0NDQ1MH0";
    private static final String JWT_SIG =
            "Or9paqnONw0QjD20IU5pYuk9VuGea1ILdhYWTJpBzA_XXrEVpv1nM9aweDTR2gpmr0XCDklq3JWH0hicVPHI5cQJeYmxwndZZ7fOxp1SILH26E"
                    + "yD2Cv7tW2wrfl03uv_fDtp1nZrSYznK26RYW9fjM00yfLnQvoaX4Lxc7DGg8A";
    private static final String JWT_FULL = JWT_HEADER + "." + JWT_PAYLOAD + "." + JWT_SIG;
    private static final String JWT_NO_SIG = JWT_HEADER + "." + JWT_PAYLOAD;

    private JwtInStorageScanRule rule;
    private ClientPassiveScanHelper helper;

    @BeforeEach
    void setUp() {
        rule = new JwtInStorageScanRule();
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
        assertThat(rule.getId(), is(120002));
        assertThat(rule.getName(), is("Information Disclosure - JWT in Browser Storage"));
        assertThat(
                rule.getHelpLink(),
                is(
                        "https://www.zaproxy.org/docs/desktop/addons/client-side-integration/pscan/#id-120002"));
        assertThat(exList.size(), is(2));
        assertThat(
                exList.get(0).getName(),
                is("Information Disclosure - JWT in Browser localStorage"));
        assertThat(exList.get(0).getParam(), is("key"));
        assertThat(exList.get(0).getPluginId(), is(120002));
        assertThat(exList.get(0).getAlertRef(), is("120002-1"));
        assertThat(exList.get(0).getConfidence(), is(3));
        assertThat(exList.get(0).getRisk(), is(2));
        assertThat(exList.get(0).getCweId(), is(200));
        assertThat(exList.get(0).getWascId(), is(13));
        assertThat(
                exList.get(1).getName(),
                is("Information Disclosure - JWT in Browser sessionStorage"));
        assertThat(exList.get(1).getParam(), is("key"));
        assertThat(exList.get(1).getPluginId(), is(120002));
        assertThat(exList.get(1).getAlertRef(), is("120002-2"));
        assertThat(exList.get(1).getConfidence(), is(3));
        assertThat(exList.get(1).getRisk(), is(0));
        assertThat(exList.get(1).getCweId(), is(200));
        assertThat(exList.get(1).getWascId(), is(13));
    }

    @ParameterizedTest
    @CsvSource({
        "localStorage," + JWT_FULL,
        "localStorage," + JWT_NO_SIG,
        "sessionStorage," + JWT_FULL,
        "sessionStorage," + JWT_NO_SIG
    })
    void shouldRaiseAlertsForStorageEvents(String type, String jwt) {
        // Given
        ReportedEvent event = getReportedEvent(type, jwt);
        // When
        rule.scanReportedObject(event, helper);
        // Then
        verify(helper).raiseAlert(any(), any());
    }

    @ParameterizedTest
    @ValueSource(strings = {"cookies", "domMutation", ""})
    void shouldNotRaiseAlertsForNonStorageEvents(String type) {
        // Given
        ReportedEvent event = getReportedEvent(type, "test");
        // When
        rule.scanReportedObject(event, helper);
        // Then
        verify(helper, times(0)).raiseAlert(any(), any());
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "NoAValidHeader." + JWT_PAYLOAD + "." + JWT_SIG,
                JWT_HEADER + ".NotAValudPayload." + JWT_SIG,
                JWT_HEADER + ".." + JWT_PAYLOAD + ".NotAValidSig",
                "dGVzdA==." + JWT_PAYLOAD + "." + JWT_SIG
            })
    void shouldNotErrorOnBadJWT(String badJwt) {
        // Given
        ReportedEvent event = getReportedEvent("localStorage", badJwt);
        // When
        rule.scanReportedObject(event, helper);
        // Then
        verify(helper, times(0)).raiseAlert(any(), any());
    }

    private static ReportedEvent getReportedEvent(String eventName, String jwt) {
        return new ReportedEvent(
                JSONObject.fromObject(
                        "{eventName='"
                                + eventName
                                + "', id = 'token', text='"
                                + jwt
                                + "', timestamp=1, count=0}"));
    }
}
