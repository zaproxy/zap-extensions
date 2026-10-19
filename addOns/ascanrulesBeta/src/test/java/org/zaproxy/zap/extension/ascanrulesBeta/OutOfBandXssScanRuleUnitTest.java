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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import fi.iki.elonen.NanoHTTPD;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.addon.oast.OastService;
import org.zaproxy.zap.testutils.NanoServerHandler;

class OutOfBandXssScanRuleUnitTest extends ActiveScannerTest<OutOfBandXssScanRule> {

    @Override
    protected OutOfBandXssScanRule createScanner() {
        return new OutOfBandXssScanRule();
    }

    @Test
    void shouldRequestHttpsPayloadForEveryExternalProbe() throws Exception {
        // Given
        nano.addHandler(
                new NanoServerHandler("/blind") {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        return newFixedLengthResponse("No callback reflected");
                    }
                });
        ExtensionOast extensionOast = mock(ExtensionOast.class);
        Control.initSingletonForTesting(Model.getSingleton(), mock(ExtensionLoader.class));
        when(Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class))
                .thenReturn(extensionOast);
        when(extensionOast.getActiveScanOastService()).thenReturn(mock(OastService.class));
        when(extensionOast.registerAlertAndGetPayload(any(), eq(true)))
                .thenReturn("secure.example.test");
        HttpMessage message = getHttpMessage("/blind?value=original");
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        verify(extensionOast, times(4)).registerAlertAndGetPayload(any(), eq(true));
        assertThat(httpMessagesSent, hasSize(4));
        for (HttpMessage sent : httpMessagesSent.subList(0, 2)) {
            assertThat(
                    sent.getRequestHeader().getURI().getQuery(),
                    containsString("https://secure.example.test"));
        }
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(79)));
        assertThat(wasc, is(equalTo(8)));
        assertThat(tags.size(), is(equalTo(12)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2025_A05_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.OWASP_2017_A07_XSS.getTag()), is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_01_REFLECTED_XSS.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_02_STORED_XSS.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.HIPAA.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.PCI_DSS.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(ExtensionOast.OAST_ALERT_TAG_KEY), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.SEQUENCE.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2025_A05_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2025_A05_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A07_XSS.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A07_XSS.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INPV_01_REFLECTED_XSS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_01_REFLECTED_XSS.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INPV_02_STORED_XSS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_02_STORED_XSS.getValue())));
        assertThat(
                tags.get(ExtensionOast.OAST_ALERT_TAG_KEY),
                is(equalTo(ExtensionOast.OAST_ALERT_TAG_VALUE)));
    }
}
