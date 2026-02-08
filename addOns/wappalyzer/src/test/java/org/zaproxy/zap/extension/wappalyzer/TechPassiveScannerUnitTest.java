/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.wappalyzer;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.emptyString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.stats.InMemoryStats;
import org.zaproxy.zap.extension.wappalyzer.ExtensionWappalyzer.Mode;
import org.zaproxy.zap.testutils.PassiveScannerTestUtils;
import org.zaproxy.zap.utils.Stats;

class TechPassiveScannerUnitTest extends PassiveScannerTestUtils<TechPassiveScanner> {

    private static final String APACHE_PHP_RESP_HEADER =
            """
            HTTP/1.1 200 OK\r
            Server: Apache\r
            X-Powered-By: PHP/5.6.34""";

    private ApplicationHolder mockApplicationHolder;
    private Map<String, List<ApplicationMatch>> siteToAppsMap = new HashMap<>();

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionWappalyzer());
    }

    @Override
    protected TechPassiveScanner createScanner() {
        resetApplicationsToSite();
        return new TechPassiveScanner(getMockApplicationHolder());
    }

    @Test
    void testApacheWithPhp() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test.php HTTP/1.1");
        msg.setResponseHeader(APACHE_PHP_RESP_HEADER);
        // When
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 2);
        assertFoundApp("https://www.example.com", "Apache");
        // No version when default (Mode.QUICK)
        assertFoundApp("https://www.example.com", "PHP", "");
    }

    @ParameterizedTest
    @CsvSource({"QUICK, ''", "EXHAUSTIVE, 5.6.34"})
    void shouldFindVersionWhenExhaustive(String mode, String phpVersion)
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test.php HTTP/1.1");
        msg.setResponseHeader(APACHE_PHP_RESP_HEADER);
        // When
        rule.setMode(Mode.valueOf(mode));
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 2);
        assertFoundApp("https://www.example.com", "Apache");
        assertFoundApp("https://www.example.com", "PHP", phpVersion);
    }

    @Test
    void shouldMatchScriptElement() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setResponseBody(
                """
                <html>
                  <script type='text/javascript' src='libs/modernizr.min.js?ver=4.1.1'>
                  </script>
                </html>""");
        // When
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 1);
        assertFoundApp("https://www.example.com", "Modernizr");
    }

    @Test
    void shouldNotMatchScriptElementContentIfNotOnScriptElement()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setResponseBody("<html><body>libs/modernizr.min.js?ver=4.1.1</body></html>");
        // When
        scan(msg);
        // Then
        assertNothingFound("https://www.example.com");
    }

    private static String buildBody(String domain, String name, String titleVersionString) {
        String titleAttribute =
                titleVersionString.isEmpty() ? "" : "title=\"" + titleVersionString + "\"";

        return """
            <html><body>
            <a href=\"https://%s\" %s style=\"border: 5px groove rgb(244, 250, 88);\">%s</a>
            </body></html>"""
                .formatted(domain, titleAttribute, name);
    }

    @Test
    void shouldMatchDomElementWithTextAndAttribute() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setResponseBody(buildBody("www.example.com", "Example", "version 1"));
        // When
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 1);
        assertFoundApp("https://www.example.com", "Test Entry");
    }

    @Test
    void shouldMatchDomElementWithOnlyText() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setResponseBody(buildBody("www.modern.com", "Modern", ""));
        // When
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 1);
        assertFoundApp("https://www.example.com", "Modernizr");
    }

    @Test
    void shouldNotMatchDomElementWithOnlyTextIfResponseNotHtml()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setResponseBody(buildBody("www.modern.com", "Modern", ""));
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "application/something");
        // When
        scan(msg);
        // Then
        assertNothingFound("https://www.example.com");
    }

    @Test
    void shouldMatchDomElementWithOnlyAttribute() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setResponseBody(buildBody("www.apache.com", "Example", "Version 1"));
        // When
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 1);
        assertFoundApp("https://www.example.com", "Apache");
    }

    @Test
    void shouldMatchSimpleDomPattern() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setResponseBody("<html><body><script src=\"sites/g/files\"></script></body></html>");
        // When
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 1);
        // No evidence on DOM selectors
        assertFoundApp("https://www.example.com", "Test Entry2", false);
    }

    @Test
    void shouldNotMatchDomElementIfNoContentMatches() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setResponseBody(buildBody("www.pinter.com", "Pinterest", "Version"));
        // When
        scan(msg);
        // Then
        assertNothingFound("https://www.example.com");
    }

    @Test
    void shouldNotMatchOnNontextResponse() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "image/x-icon");
        // Purposefully set the body to something that should match but be ignored
        msg.setResponseBody("<html><script src=\"/bitrix/js\"></script></html>");
        // When
        scan(msg);
        // Then
        assertNothingFound("https://www.example.com");
    }

    @Test
    void shouldMatchOnNontextResponseWhenHeaderMatches() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "image/x-icon");
        msg.getResponseHeader().setHeader("X-Powered-CMS", "Bitrix Site Manager");
        // Purposefully set the body to something that should match but be ignored
        msg.setResponseBody("<html><script src=\"/bitrix/js\"></script></html>");
        // When
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 2);
        assertFoundApp("https://www.example.com", "1C-Bitrix"); // Matched
        // No evidence when implied
        assertFoundApp("https://www.example.com", "PHP", false); // Implied
    }

    @Test
    void shouldMatchOnCssResponseWhenContentMatches() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "text/css");
        msg.setResponseBody(".example {background-color: lightblue;}");
        // When
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 1);
        assertFoundApp("https://www.example.com", "Test Entry");
    }

    @Test
    void shouldMatchOnCssRequestWhenContentMatches() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setRequestHeader("GET https://www.example.com/styles.css HTTP/1.1");
        msg.setResponseBody(".example {background-color: lightblue;}");
        // When
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 1);
        assertFoundApp("https://www.example.com", "Test Entry");
    }

    @Test
    void shouldMatchOnHtmlResponseWhenContentStyleMatches() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setResponseBody(
                "<html><head><style>.example {background-color: lightblue;}</style></head></html>");
        // When
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 1);
        assertFoundApp("https://www.example.com", "Test Entry");
    }

    @Test
    void shouldNotMatchOnHtmlResponseWhenContentStyleDoesNotMatch()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setResponseBody(
                "<html><head><style>.TEST {background-color: lightblue;}</style></head></html>");
        // When
        scan(msg);
        // Then
        assertNothingFound("https://www.example.com");
    }

    @Test
    void shouldMatchOnMetaTag() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setResponseBody(
                "<html><head><meta name=\"generator\" content=\"Apache\"></head></html>");
        // When
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 1);
        assertFoundApp("https://www.example.com", "Apache");
    }

    @Test
    void shouldMatchOnMetaTagWithMultipleEntries() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setResponseBody(
                "<html><head><meta name=\"generator\" content=\"Generator 2\"></head></html>");
        // When
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 1);
        assertFoundApp("https://www.example.com", "Test Entry");
    }

    @Test
    void shouldMatchCookieNameWithPhp() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Set-Cookie: PHPSESSID=foo");
        // When
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 1);
        assertFoundApp("https://www.example.com", "PHP");
    }

    @Test
    void shouldMatchCookieNameInRequestWithPhp() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test HTTP/1.1");
        msg.getRequestHeader().addHeader(HttpHeader.COOKIE, "PHPSESSID=foo");
        // When
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 1);
        assertFoundApp("https://www.example.com", "PHP");
    }

    @Test
    void shouldMatchCookieNameAndValueWithTestEntry() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Set-Cookie: foo=bar");
        // When
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 1);
        assertFoundApp("https://www.example.com", "Test Entry");
    }

    @Test
    void shouldMatchCookieNameAndValueInRequestWithTestEntry() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test HTTP/1.1");
        msg.getRequestHeader().addHeader(HttpHeader.COOKIE, "foo=bar");
        // When
        scan(msg);
        // Then
        assertFoundAppCount("https://www.example.com", 1);
        assertFoundApp("https://www.example.com", "Test Entry");
    }

    @Test
    void shouldNotMatchCookieNameAndWrongValueWithTestEntry() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Set-Cookie: foo=foo");
        // When
        scan(msg);
        // Then
        assertNothingFound("https://www.example.com");
    }

    @Test
    void shouldNotMatchCookieNameAndWrongValueInRequestWithTestEntry()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test HTTP/1.1");
        msg.getRequestHeader().addHeader(HttpHeader.COOKIE, "foo=foo");
        // When
        scan(msg);
        // Then
        assertNothingFound("https://www.example.com");
    }

    @Test
    void shouldNotMatchOnlyCookieNameWhenValueIsAlsoExpected() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test HTTP/1.1");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Set-Cookie: foo");
        // When
        scan(msg);
        // Then
        assertNothingFound("https://www.example.com");
    }

    @Test
    void shouldNotMatchOnlyCookieNameInRequestWhenValueIsAlsoExpected()
            throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = makeHttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test HTTP/1.1");
        msg.getRequestHeader().addHeader(HttpHeader.COOKIE, "foo");
        // When
        scan(msg);
        // Then
        assertNothingFound("https://www.example.com");
    }

    @Test
    void shouldMatchHeaderNameAndValueInRequestWhenBothExpected()
            throws HttpMalformedHeaderException {
        // Given
        String site = "https://www.example.com";
        HttpMessage msg = makeHttpMessage();
        msg.setRequestHeader("GET " + site + "/test HTTP/1.1");
        msg.getResponseHeader().addHeader("Test", "Test Entry");
        // When
        scan(msg);
        // Then
        assertFoundAppCount(site, 1);
        assertFoundApp(site, "Test Entry");
    }

    @Test
    void shouldNotMatchHeaderNameAndValueInRequestWhenBothExpectedAndValueNotPresent()
            throws HttpMalformedHeaderException {
        // Given
        String site = "https://www.example.com";
        HttpMessage msg = makeHttpMessage();
        msg.setRequestHeader("GET " + site + "/test HTTP/1.1");
        msg.getResponseHeader().addHeader("Test", "");
        // When
        scan(msg);
        // Then
        assertNothingFound(site);
    }

    @Test
    void shouldMatchHeaderNameInRequestWhenValueNotExpected() throws HttpMalformedHeaderException {
        // Given
        String site = "https://www.example.com";
        HttpMessage msg = makeHttpMessage();
        msg.setRequestHeader("GET " + site + "/test HTTP/1.1");
        msg.getResponseHeader().addHeader("Foo", "");
        // When
        scan(msg);
        // Then
        assertFoundAppCount(site, 1);
        assertFoundApp(site, "Test Entry");
    }

    @Test
    void shouldNotMatchMultipleTimesAgainstSameMessage() throws HttpMalformedHeaderException {
        // Given
        String site = "https://www.example.com";
        HttpMessage msg = makeHttpMessage();
        msg.setRequestHeader("GET " + site + "/test HTTP/1.1");
        msg.getResponseHeader().addHeader("Test", "Test Entry");
        // When
        scan(msg);
        int initialCount = siteToAppsMap.get(site).size();
        scan(msg);
        int secondaryCount = siteToAppsMap.get(site).size();
        // Then
        assertThat(initialCount, is(equalTo(secondaryCount)));
        assertFoundAppCount(site, 1);
        assertFoundApp(site, "Test Entry");
    }

    @Test
    void shouldMaintainStats() throws HttpMalformedHeaderException {
        // Given
        Stats.clearAll();
        InMemoryStats stats = new InMemoryStats();
        Stats.addListener(stats);
        String site = "https://www.example.com";
        HttpMessage msg1 = makeHttpMessage(site + "/test1");
        msg1.getResponseHeader().addHeader("Test", "Test Entry");
        HttpMessage msg2 = makeHttpMessage(site + "/test2");
        msg2.setRequestHeader("GET " + site + "/test2 HTTP/1.1");
        msg2.getResponseHeader().addHeader("Test", "Test Entry");
        HttpMessage msg3 = makeHttpMessage(site + "/test3");
        msg3.setRequestHeader("GET " + site + "/test3 HTTP/1.1");
        // When
        scan(msg1);
        scan(msg2);
        scan(msg3);
        // Then
        assertFoundAppCount(site, 1);
        assertFoundApp(site, "Test Entry");
        assertThat(stats.getStat(site, "stats.tech.reqcount.id"), is(2L));
        // Note that this should be 3 but there's a bug in the core
        assertThat(stats.getStat(site, "stats.tech.reqcount.total"), is(4L));

        Stats.removeListener(stats);
    }

    @Test
    void shouldHaveHelpLink() {
        // Given / When
        String helpLink = rule.getHelpLink();
        // Then
        assertThat(helpLink, is(not(emptyString())));
    }

    private void scan(HttpMessage msg) {
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));
    }

    private static HttpMessage makeHttpMessage() throws HttpMalformedHeaderException {
        return makeHttpMessage("https://www.example.com/");
    }

    private static HttpMessage makeHttpMessage(String url) throws HttpMalformedHeaderException {
        HttpMessage httpMessage = new HttpMessage();

        HistoryReference ref = mock(HistoryReference.class);

        httpMessage.setHistoryRef(ref);

        httpMessage.setRequestHeader("GET " + url + " HTTP/1.1");
        httpMessage.setResponseHeader("HTTP/1.1 200 OK");
        httpMessage.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "text/html");
        return httpMessage;
    }

    private void assertNothingFound(String site) {
        List<ApplicationMatch> appsForSite = siteToAppsMap.get(site);
        assertNull(appsForSite);
    }

    private void assertFoundAppCount(String site, int appCount) {
        List<ApplicationMatch> appsForSite = siteToAppsMap.get(site);
        assertThat(appsForSite, notNullValue());
        assertThat(appsForSite.size(), is(appCount));
    }

    private void assertFoundApp(String site, String appName) {
        assertFoundApp(site, appName, null, true);
    }

    private void assertFoundApp(String site, String appName, boolean withEvidence) {
        assertFoundApp(site, appName, null, withEvidence);
    }

    private void assertFoundApp(String site, String appName, String version) {
        assertFoundApp(site, appName, version, true);
    }

    private void assertFoundApp(String site, String appName, String version, boolean withEvidence) {
        List<ApplicationMatch> appsForSite = siteToAppsMap.get(site);
        assertThat(appsForSite, notNullValue());

        Optional<ApplicationMatch> app =
                appsForSite.stream()
                        .filter(a -> Objects.equals(a.getApplication().getName(), appName))
                        .findFirst();

        assertThat("Application '" + appName + "' not present", app.isPresent(), is(true));
        if (version != null) {
            assertThat(app.get().getVersion(), is(version));
        }
        if (withEvidence) {
            assertThat(app.get().getEvidences(), is(not(empty())));
        }
    }

    @Nested
    class AlertsUnitTest extends PassiveScannerTestUtils<TechPassiveScanner> {

        @Override
        protected TechPassiveScanner createScanner() {
            resetApplicationsToSite();
            return new TechPassiveScanner(getMockApplicationHolder());
        }

        @Test
        void shouldHaveCpeAndVersionInAlertIfAvailable() throws HttpMalformedHeaderException {
            // Given
            HttpMessage msg = new HttpMessage();
            msg.setRequestHeader("GET https://www.example.com/test HTTP/1.1");
            msg.getResponseHeader().addHeader("Server", "Apache/2.4.7 (Ubuntu)");
            // When
            Application app = new Application();
            app.setCpe("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*");
            ApplicationMatch appMatch = new ApplicationMatch(app);
            appMatch.addVersion("2.4.7");
            Alert alert =
                    rule.createAlert(msg.getRequestHeader().getURI().toString(), appMatch).build();
            // Then
            assertThat(
                    alert.getOtherInfo(),
                    is(
                            equalTo(
                                    "The following CPE is associated with the identified tech: cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*\n"
                                            + "The following version(s) is/are associated with the identified tech: 2.4.7")));
            assertThat(alert.getWascId(), is(equalTo(13)));
        }

        @Test
        void shouldNotHaveCpeAndVersionInAlertIfNotAvailablet()
                throws HttpMalformedHeaderException {
            // Given
            HttpMessage msg = new HttpMessage();
            msg.setRequestHeader("GET https://www.example.com/test HTTP/1.1");
            msg.getResponseHeader().addHeader("Server", "Apache/2.4.7 (Ubuntu)");
            // When
            Application app = new Application();
            ApplicationMatch appMatch = new ApplicationMatch(app);
            Alert alert =
                    rule.createAlert(msg.getRequestHeader().getURI().toString(), appMatch).build();
            // Then
            assertThat(alert.getOtherInfo(), is(equalTo("")));
            assertThat(alert.getReference(), is(equalTo("")));
            assertThat(alert.getWascId(), is(equalTo(13)));
        }

        @Test
        void shouldHaveRefInAlertIfWebsiteAvailable() throws HttpMalformedHeaderException {
            // Given
            HttpMessage msg = new HttpMessage();
            msg.setRequestHeader("GET https://www.example.com/test HTTP/1.1");
            msg.getResponseHeader().addHeader("Server", "Apache/2.4.7 (Ubuntu)");
            // When
            Application app = new Application();
            app.setWebsite("https://httpd.apache.org");
            ApplicationMatch appMatch = new ApplicationMatch(app);
            Alert alert =
                    rule.createAlert(msg.getRequestHeader().getURI().toString(), appMatch).build();
            // Then
            assertThat(alert.getOtherInfo(), is(equalTo("")));
            assertThat(alert.getReference(), is(equalTo("https://httpd.apache.org")));
            assertThat(alert.getWascId(), is(equalTo(13)));
        }

        @Test
        void shouldHaveExpectedExampleAlert() {
            // Given / When
            List<Alert> alerts = rule.getExampleAlerts();
            // Then
            assertThat(alerts, hasSize(1));
            Alert alert = alerts.get(0);
            assertThat(alert.getName(), is(equalTo("Tech Detection Passive Scanner")));
            assertThat(
                    alert.getDescription(),
                    is(
                            equalTo(
                                    "The following \"Widgets\" technology was identified: Example Software.")));
            assertThat(alert.getRisk(), is(equalTo(Alert.RISK_INFO)));
            assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
            assertThat(alert.getEvidence(), is(equalTo("Exampleware")));
            assertThat(
                    alert.getOtherInfo(),
                    is(
                            equalTo(
                                    "The following CPE is associated with the identified tech: cpe:2.3:a:example_vendor:example_software:55.4.3:*:*:*:*:*:*:*\n"
                                            + "The following version(s) is/are associated with the identified tech: 55.4.3")));
            assertThat(alert.getWascId(), is(equalTo(13)));
        }
    }

    public ApplicationHolder getMockApplicationHolder() {
        if (mockApplicationHolder == null) {
            mockApplicationHolder =
                    mock(ApplicationHolder.class, withSettings().strictness(Strictness.LENIENT));

            List<Application> applications = createTestApplications();
            given(mockApplicationHolder.getApplications()).willReturn(applications);

            given(mockApplicationHolder.getApplication(anyString()))
                    .willAnswer(
                            invocation -> {
                                String name = invocation.getArgument(0);
                                return applications.stream()
                                        .filter(app -> name.equals(app.getName()))
                                        .findFirst()
                                        .orElse(null);
                            });

            // Capture addApplicationsToSite calls and track them
            doAnswer(
                            invocation -> {
                                String site = invocation.getArgument(0);
                                ApplicationMatch match = invocation.getArgument(1);
                                siteToAppsMap
                                        .computeIfAbsent(site, k -> new ArrayList<>())
                                        .add(match);
                                return null;
                            })
                    .when(mockApplicationHolder)
                    .addApplicationsToSite(anyString(), any(ApplicationMatch.class));
        }
        return mockApplicationHolder;
    }

    private void resetApplicationsToSite() {
        siteToAppsMap.clear();
    }

    private List<Application> createTestApplications() {
        TechsJsonParser parser = new TechsJsonParser();
        TechData techData = parser.parse("categories.json", List.of("apps.json"), false);
        return techData.getApplications();
    }
}
