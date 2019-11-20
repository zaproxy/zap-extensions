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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ascanrulesAlpha.HiddenFilesScanRule.HiddenFile;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.StaticContentServerHandler;

/**
 * Unit Test for HiddenFilesScanRule.
 *
 * <p>Note: If using {@code setPayloadProvider(Supplier)} should be called before {@code
 * rule.init()}</br> Note: If using {@code addTestPayload(HiddenFile)} should be called after {@code
 * rule.init()}
 */
public class HiddenFilesScanRuleUnitTest extends ActiveScannerTest<HiddenFilesScanRule> {

    @Override
    protected HiddenFilesScanRule createScanner() {
        return new HiddenFilesScanRule();
    }

    @Before
    public void before() {
        HiddenFilesScanRule.setPayloadProvider(null);
    }

    @Test
    public void shouldRaiseAlertIfTestedUrlRespondsOkWithRelevantContent()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "foo/test.php";
        List<String> contents = Arrays.asList("Awesome");
        List<String> links = Arrays.asList("https://example.org");
        HiddenFile hiddenFile = new HiddenFile(testPath, contents, links, "test_php");

        this.nano.addHandler(new OkResponseWithReqPath(servePath));
        this.nano.addHandler(
                new StaticContentServerHandler(
                        '/' + testPath,
                        "<html><head></head><H>Awesome Title</H1> Some Text... <html>"));

        HttpMessage msg = this.getHttpMessage(servePath);

        rule.init(msg, this.parent);
        HiddenFilesScanRule.addTestPayload(hiddenFile);

        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals(1, httpMessagesSent.size());
        assertEquals(Alert.RISK_MEDIUM, alertsRaised.get(0).getRisk());
        assertEquals(Alert.CONFIDENCE_HIGH, alertsRaised.get(0).getConfidence());
        assertEquals(hiddenFile.getType(), alert.getOtherInfo());
        assertEquals(
                rule.getReference() + '\n' + hiddenFile.getLinks().get(0), alert.getReference());
    }

    @Test
    public void shouldRaiseAlertIfTestedUrlRespondsForbidden() throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "foo/test.php";
        List<String> contents = Arrays.asList("Awesome");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile = new HiddenFile(testPath, contents, links, "test_php");

        this.nano.addHandler(new OkResponseWithReqPath(servePath));
        this.nano.addHandler(new ForbiddenResponseWithReqPath("/" + testPath));

        HttpMessage msg = this.getHttpMessage(servePath);

        rule.init(msg, this.parent);
        HiddenFilesScanRule.addTestPayload(hiddenFile);

        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals(1, httpMessagesSent.size());
        assertEquals(Alert.RISK_INFO, alertsRaised.get(0).getRisk());
        assertEquals(Alert.CONFIDENCE_LOW, alertsRaised.get(0).getConfidence());
        assertEquals(hiddenFile.getType(), alert.getOtherInfo());
    }

    @Test
    public void shouldNotRaiseAlertIfPathIsntServed() throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldNotAlert";

        String testPath = "foo/test.php";
        List<String> contents = Arrays.asList("Awesome");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile = new HiddenFile(testPath, contents, links, "test_php");

        this.nano.addHandler(new OkResponseWithReqPath(servePath));
        this.nano.addHandler(new ForbiddenResponseWithReqPath("/fred.php"));

        HttpMessage msg = this.getHttpMessage(servePath);

        rule.init(msg, this.parent);
        HiddenFilesScanRule.addTestPayload(hiddenFile);

        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertEquals(1, httpMessagesSent.size());
    }

    @Test
    public void shouldAlertWithMediumConfidenceIfContentStringsDontAllMatch()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "foo/test.php";
        List<String> contents = Arrays.asList("Site", "StringNotFound");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile = new HiddenFile(testPath, contents, links, "test_php");

        this.nano.addHandler(new OkResponseWithReqPath(servePath));
        this.nano.addHandler(new OkResponseWithReqPath("/" + testPath));

        HttpMessage msg = this.getHttpMessage(servePath);

        rule.init(msg, this.parent);
        HiddenFilesScanRule.addTestPayload(hiddenFile);

        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals(1, httpMessagesSent.size());
        assertEquals(Alert.RISK_MEDIUM, alertsRaised.get(0).getRisk());
        assertEquals(Alert.CONFIDENCE_MEDIUM, alertsRaised.get(0).getConfidence());
        assertEquals(hiddenFile.getType(), alert.getOtherInfo());
        assertEquals(rule.getReference(), alert.getReference());
    }

    @Test
    public void shouldRaiseAlertWithHighConfidenceIfContentStringsAllMatch()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "foo/test.php";
        List<String> contents = Arrays.asList("Site", "Text");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile = new HiddenFile(testPath, contents, links, "test_php");

        this.nano.addHandler(new OkResponseWithReqPath(servePath));
        this.nano.addHandler(new OkResponseWithReqPath("/" + testPath));

        HttpMessage msg = this.getHttpMessage(servePath);

        rule.init(msg, this.parent);
        HiddenFilesScanRule.addTestPayload(hiddenFile);

        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals(1, httpMessagesSent.size());
        assertEquals(Alert.RISK_MEDIUM, alertsRaised.get(0).getRisk());
        assertEquals(Alert.CONFIDENCE_HIGH, alertsRaised.get(0).getConfidence());
        assertEquals(hiddenFile.getType(), alert.getOtherInfo());
        assertEquals(rule.getReference(), alert.getReference());
    }

    @Test
    public void shouldRaiseAlertIfTestedUrlRespondsOkToCustomPayloadWithoutRelevantContent()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "foo/test.php";
        List<String> testPaths = Arrays.asList(testPath);

        this.nano.addHandler(new OkResponseWithReqPath(servePath));
        this.nano.addHandler(
                new StaticContentServerHandler(
                        '/' + testPath,
                        "<html><head></head><H>Awesome Title</H1> Some Text... <html>"));

        HttpMessage msg = this.getHttpMessage(servePath);

        HiddenFilesScanRule.setPayloadProvider(() -> testPaths);
        rule.init(msg, this.parent);

        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertEquals(1, httpMessagesSent.size());
        assertEquals(Alert.RISK_MEDIUM, alertsRaised.get(0).getRisk());
        assertEquals(Alert.CONFIDENCE_MEDIUM, alertsRaised.get(0).getConfidence());
        assertEquals(rule.getReference(), alert.getReference());
    }

    @Test
    public void shouldNotRaiseAlertIfResponseStatusIsNotOkOrAuthRelated()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldNotAlert";

        String testPath = "foo/test.php";
        List<String> contents = Arrays.asList("Site", "Text");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile = new HiddenFile(testPath, contents, links, "test_php");

        this.nano.addHandler(new OkResponseWithReqPath(servePath));
        this.nano.addHandler(new NotFoundResponseWithReqPath("/" + testPath));

        HttpMessage msg = this.getHttpMessage(servePath);

        rule.init(msg, this.parent);
        HiddenFilesScanRule.addTestPayload(hiddenFile);

        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertEquals(1, httpMessagesSent.size());
    }

    private static class ForbiddenResponseWithReqPath extends NanoServerHandler {

        private static final String PATH_TOKEN = "@@@PATH@@@";
        private static final String FORBIDDEN_RESPONSE_WITH_REQUESTED_PATH =
                "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                        + "<html><head>\n"
                        + "<title>403 Forbidden</title>\n"
                        + "</head><body>\n"
                        + "<h1>Forbidden</h1>\n"
                        + "<p>You don't have permission to access "
                        + PATH_TOKEN
                        + "\n"
                        + "on this server.</p>\n"
                        + "</body></html>";

        public ForbiddenResponseWithReqPath(String path) {
            super(path);
        }

        @Override
        protected Response serve(IHTTPSession session) {
            return NanoHTTPD.newFixedLengthResponse(
                    Response.Status.FORBIDDEN,
                    "text/html",
                    FORBIDDEN_RESPONSE_WITH_REQUESTED_PATH.replace(PATH_TOKEN, session.getUri()));
        }
    }

    private static class NotFoundResponseWithReqPath extends NanoServerHandler {

        private static final String NOT_FOUND_RESPONSE =
                "<!DOCTYPE html\">\n"
                        + "<html><head></head><H>Four oh four</H1>Not found... <html>";

        public NotFoundResponseWithReqPath(String path) {
            super(path);
        }

        @Override
        protected Response serve(IHTTPSession session) {
            return NanoHTTPD.newFixedLengthResponse(
                    Response.Status.NOT_FOUND, "text/html", NOT_FOUND_RESPONSE);
        }
    }

    private static class OkResponseWithReqPath extends StaticContentServerHandler {

        private static final String OK_RESPONSE =
                "<!DOCTYPE html\">\n" + "<html><head></head><H>Site Title</H1>Site Text... <html>";

        public OkResponseWithReqPath(String path) {
            super(path, OK_RESPONSE);
        }
    }
}
