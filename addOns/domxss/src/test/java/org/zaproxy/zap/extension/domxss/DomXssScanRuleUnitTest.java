/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.domxss;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import io.github.bonigarcia.wdm.WebDriverManager;
import java.io.IOException;
import java.util.stream.Stream;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.testutils.ActiveScannerTestUtils;
import org.zaproxy.zap.testutils.NanoServerHandler;

public class DomXssScanRuleUnitTest extends ActiveScannerTestUtils<DomXssScanRule> {

    @BeforeAll
    static void setup() {
        WebDriverManager.firefoxdriver().setup();
        WebDriverManager.chromedriver().setup();
    }

    static Stream<String> testBrowsers() throws Exception {
        // TODO chrome-headless is failing in travis - need to investigate at some point
        return Stream.of("firefox-headless");
    }

    @AfterAll
    static void tidyUp() {
        DomXssScanRule.tidyUp();
    }

    @Override
    protected DomXssScanRule createScanner() {
        return new DomXssScanRule();
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionDomXSS());
    }

    @Test
    public void shouldUseDefaultWhenUnsupportedBrowser() throws IOException {
        // Given
        HttpMessage msg = this.getHttpMessage("");
        this.rule.getConfig().setProperty("rules.domxss.browserid", "opera");
        this.rule.init(msg, this.parent);

        // When / Then
        assertThat(this.rule.getBrowser(), equalTo(Browser.FIREFOX_HEADLESS));
    }

    @Test
    public void shouldUseDefaultWhenUnknownBrowser() throws IOException {
        // Given
        HttpMessage msg = this.getHttpMessage("");
        this.rule.getConfig().setProperty("rules.domxss.browserid", "invalid");
        this.rule.init(msg, this.parent);

        // When / Then
        assertThat(this.rule.getBrowser(), equalTo(Browser.FIREFOX_HEADLESS));
    }

    @ParameterizedTest
    @MethodSource("testBrowsers")
    public void shouldUseCorrectBrowser(String browser) throws IOException {
        // Given
        HttpMessage msg = this.getHttpMessage("");
        this.rule.getConfig().setProperty("rules.domxss.browserid", browser);
        this.rule.init(msg, this.parent);

        // When / Then
        assertThat(this.rule.getBrowser(), equalTo(Browser.getBrowserWithId(browser)));
    }

    /** Test based on http://public-firing-range.appspot.com/address/location.hash/assign */
    @ParameterizedTest
    @MethodSource("testBrowsers")
    public void shouldReportXssInLocationHashAssign(String browser)
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssInLocationHashAssign/";

        this.nano.addHandler(new TestNanoServerHandler(test, "LocationHashAssign.html"));

        HttpMessage msg = this.getHttpMessage(test);
        this.rule.getConfig().setProperty("rules.domxss.browserid", browser);
        this.rule.init(msg, this.parent);

        // When
        this.rule.scan();

        // Then
        assertAlertsRaised();
    }

    /** Alerts raised are timing dependent, so any of these are good. */
    private void assertAlertsRaised() {
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
        assertThat(alertsRaised.get(0).getParam(), equalTo(""));
        assertThat(
                alertsRaised.get(0).getAttack(),
                Matchers.anyOf(
                        equalTo(DomXssScanRule.POLYGLOT_ALERT),
                        equalTo(DomXssScanRule.HASH_JAVASCRIPT_ALERT),
                        equalTo(DomXssScanRule.QUERY_HASH_IMG_ALERT)));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    /** Test based on http://public-firing-range.appspot.com/address/location.hash/eval */
    @ParameterizedTest
    @MethodSource("testBrowsers")
    public void shouldReportXssInLocationHashEval(String browser)
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssInLocationHashEval/";

        this.nano.addHandler(new TestNanoServerHandler(test, "LocationHashEval.html"));

        HttpMessage msg = this.getHttpMessage(test);
        this.rule.getConfig().setProperty("rules.domxss.browserid", browser);
        this.rule.init(msg, this.parent);

        // When
        this.rule.scan();

        // Then
        assertAlertsRaised();
    }

    /** Test based on http://public-firing-range.appspot.com/address/location.hash/replace */
    @ParameterizedTest
    @MethodSource("testBrowsers")
    public void shouldReportXssInLocationHashReplace(String browser)
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssInLocationHashReplace/";

        this.nano.addHandler(new TestNanoServerHandler(test, "LocationHashReplace.html"));

        HttpMessage msg = this.getHttpMessage(test);
        this.rule.getConfig().setProperty("rules.domxss.browserid", browser);
        this.rule.init(msg, this.parent);

        // When
        this.rule.scan();

        // Then
        assertAlertsRaised();
    }

    /** Test based on http://public-firing-range.appspot.com/address/location.hash/setTimeout */
    @ParameterizedTest
    @MethodSource("testBrowsers")
    public void shouldReportXssInLocationHashSetTimeout(String browser)
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssInLocationHashSetTimeout/";

        this.nano.addHandler(new TestNanoServerHandler(test, "LocationHashSetTimeout.html"));

        HttpMessage msg = this.getHttpMessage(test);
        this.rule.getConfig().setProperty("rules.domxss.browserid", browser);
        this.rule.init(msg, this.parent);

        // When
        this.rule.scan();

        // Then
        assertAlertsRaised();
    }

    /** Test to trigger XSS after cancel button is clicked */
    @ParameterizedTest
    @MethodSource("testBrowsers")
    public void shouldReportXssWhenCancelButtonIsClicked(String browser)
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssWhenCancelButtonIsClicked/";

        this.nano.addHandler(new TestNanoServerHandler(test, "CancelButton.html"));

        HttpMessage msg = this.getHttpMessage(test + "?returnUrl=javascript:alert()");
        this.rule.getConfig().setProperty("rules.domxss.browserid", browser);

        this.rule.init(msg, this.parent);

        // When
        this.rule.scan();

        // Then
        assertAlertsRaised();
    }

    /** Test based on http://public-firing-range.appspot.com/address/location.hash/function */
    @ParameterizedTest
    @MethodSource("testBrowsers")
    public void shouldReportXssInLocationHashFunction(String browser)
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssInLocationHashFunction/";

        this.nano.addHandler(new TestNanoServerHandler(test, "LocationHashFunction.html"));

        HttpMessage msg = this.getHttpMessage(test);
        this.rule.getConfig().setProperty("rules.domxss.browserid", browser);
        this.rule.init(msg, this.parent);

        // When
        this.rule.scan();

        // Then
        assertAlertsRaised();
    }

    /** Test based on http://public-firing-range.appspot.com/address/location.hash/jshref */
    @ParameterizedTest
    @MethodSource("testBrowsers")
    public void shouldReportXssInLocationHashInlineEvent(String browser)
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssInLocationHashInlineEvent/";

        this.nano.addHandler(new TestNanoServerHandler(test, "LocationHashInlineEvent.html"));

        HttpMessage msg = this.getHttpMessage(test);
        this.rule.getConfig().setProperty("rules.domxss.browserid", browser);
        this.rule.init(msg, this.parent);

        // When
        this.rule.scan();

        // Then
        assertAlertsRaised();
    }

    /** Test based on http://public-firing-range.appspot.com/address/location.hash/formaction */
    @ParameterizedTest
    @MethodSource("testBrowsers")
    public void shouldReportXssInLocationHashFormAction(String browser)
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssInLocationHashFormAction/";

        this.nano.addHandler(new TestNanoServerHandler(test, "LocationHashFormAction.html"));

        HttpMessage msg = this.getHttpMessage(test);
        this.rule.getConfig().setProperty("rules.domxss.browserid", browser);
        this.rule.init(msg, this.parent);

        // When
        this.rule.scan();

        // Then
        assertAlertsRaised();
    }

    /**
     * Test based on
     * http://public-firing-range.appspot.com/dom/eventtriggering/document/formSubmission/innerHtml
     * Note that this only works in Firefox, not Chrome.
     */
    @Test
    public void shouldReportXssInEventInnerHtmlFirefox() throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssInEventInnerHtml/";

        this.nano.addHandler(new TestNanoServerHandler(test, "EventInnerHtml.html"));

        HttpMessage msg = this.getHttpMessage(test);
        this.rule
                .getConfig()
                .setProperty("rules.domxss.browserid", Browser.FIREFOX_HEADLESS.name());
        this.rule.init(msg, this.parent);

        // When
        this.rule.scan();

        // Then
        assertAlertsRaised();
    }

    /**
     * Test based on
     * http://public-firing-range.appspot.com/dom/eventtriggering/document/inputTyping/innerHtml
     */
    @ParameterizedTest
    @MethodSource("testBrowsers")
    public void shouldReportXssInTypingInnerHtml(String browser)
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssInTypingInnerHtml/";

        this.nano.addHandler(new TestNanoServerHandler(test, "TypingInnerHtml.html"));

        HttpMessage msg = this.getHttpMessage(test);
        this.rule.getConfig().setProperty("rules.domxss.browserid", browser);
        this.rule.init(msg, this.parent);

        // When
        this.rule.scan();

        // Then
        assertAlertsRaised();
    }

    /**
     * Test based on
     * http://public-firing-range.appspot.com/dom/eventtriggering/document/inputTyping/innerHtml
     */
    @ParameterizedTest
    @MethodSource("testBrowsers")
    public void shouldReportXssInDomPropagation(String browser)
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssInDomPropagation/";

        this.nano.addHandler(new TestNanoServerHandler(test, "DomPropagation.html"));

        HttpMessage msg = this.getHttpMessage(test);
        this.rule.getConfig().setProperty("rules.domxss.browserid", browser);
        this.rule.init(msg, this.parent);

        // When
        this.rule.scan();

        // Then
        assertAlertsRaised();
    }

    private class TestNanoServerHandler extends NanoServerHandler {
        private String fileName;

        public TestNanoServerHandler(String name, String fileName) {
            super(name);
            this.fileName = fileName;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String response = getHtml(fileName);
            return newFixedLengthResponse(response);
        }
    }
}
