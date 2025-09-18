/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.StaticContentServerHandler;

/** Unit test for {@link XsltInjectionScanRule}. */
class XsltInjectionScanRuleUnitTest extends ActiveScannerTest<XsltInjectionScanRule> {

    @Override
    protected XsltInjectionScanRule createScanner() {
        return new XsltInjectionScanRule();
    }

    @Test
    void shouldNotAlertIfResponseDoesNotContainRelevantContent() throws Exception {
        // Given
        String path = "/shouldNotAlert";

        this.nano.addHandler(
                new StaticContentServerHandler(
                        path, "<html><head></head><H>Awesome Title</H1> Some Text... <html>"));

        HttpMessage msg = this.getHttpMessage(path + "?name=test");
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertEquals(httpMessagesSent.size(), 8);
    }

    @Test
    void shouldAlertIfResponseContainsRelevantErrorString() throws Exception {
        // Given
        String path = "/shouldReportError";
        String errorString = "XSLT compile error";

        this.nano.addHandler(
                new StaticContentServerHandler(path, "<html>Uh oh " + errorString + ".<html>"));

        HttpMessage msg = this.getHttpMessage(path + "?name=test");
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals(alertsRaised.get(0).getName(), "XSLT Injection");
        assertThat(alertsRaised.get(0).getEvidence(), is("XSLT compile error"));
        assertEquals(alertsRaised.get(0).getRisk(), Alert.RISK_MEDIUM);
        assertThat(alertsRaised.get(0).getParam(), is("name"));
    }

    @Test
    void shouldAlertIfResponseContainsVendorString() throws Exception {
        // Given
        String path = "/shouldReportVendor";
        String vendorString = "Saxon-CE 1.1 from Saxonica";

        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String value = getFirstParamValue(session, "name");
                        if (value != null && value.contains("vedor")) {
                            return newFixedLengthResponse(
                                    "<!DOCTYPE html><html><body>Nothing to see here.</body></html>");
                        }
                        return newFixedLengthResponse("<html>" + vendorString + "<html>");
                    }
                });

        HttpMessage msg = this.getHttpMessage(path + "?name=test");
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals(alertsRaised.get(0).getName(), "XSLT Injection");
        assertThat(alertsRaised.get(0).getEvidence(), is("Saxonica"));
        assertEquals(alertsRaised.get(0).getRisk(), Alert.RISK_MEDIUM);
        assertThat(alertsRaised.get(0).getParam(), is("name"));
    }

    @Test
    void shouldNotAlertIfResponsesBothContainVendorString() throws Exception {
        // Given
        String path = "/";
        String vendorString = "Apache Xalan";

        nano.addHandler(
                new NanoServerHandler(path) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String value = getFirstParamValue(session, "name");
                        if (value != null && value.contains("vedor")) {
                            return newFixedLengthResponse(
                                    "<!DOCTYPE html><html><h3>Apache Tomcat/7.0.92</h3></body></html>");
                        }
                        return newFixedLengthResponse("<html>" + vendorString + "<html>");
                    }
                });

        HttpMessage msg = this.getHttpMessage(path + "?name=test");
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(91)));
        assertThat(wasc, is(equalTo(23)));
        assertThat(tags.size(), is(equalTo(13)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.HIPAA.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.PCI_DSS.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.API.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.SEQUENCE.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A01_INJECTION.getValue())));
    }

    @Test
    void shouldHaveExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts, hasSize(1));
        Alert alert = alerts.get(0);
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alert.getAlertRef(), is(equalTo("90017")));
    }
}
