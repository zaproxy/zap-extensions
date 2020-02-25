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
import java.nio.charset.StandardCharsets;
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
        HiddenFile hiddenFile =
                new HiddenFile(testPath, contents, Collections.emptyList(), "", links, "test_php");

        this.nano.addHandler(new OkResponse(servePath));
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
    public void shouldRaiseAlertWithLowConfidenceIfTestedUrlRespondsForbidden()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "foo/test.php";
        List<String> contents = Arrays.asList("Awesome");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile =
                new HiddenFile(testPath, contents, Collections.emptyList(), "", links, "test_php");

        this.nano.addHandler(new OkResponse(servePath));
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
        HiddenFile hiddenFile =
                new HiddenFile(testPath, contents, Collections.emptyList(), "", links, "test_php");

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(new OkResponse("/fred.php"));

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
    public void shouldAlertWithLowConfidenceIfContentStringsDontAllMatch()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "foo/test.php";
        List<String> contents = Arrays.asList("Site", "StringNotFound");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile =
                new HiddenFile(testPath, contents, Collections.emptyList(), "", links, "test_php");

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(new OkResponse("/" + testPath));

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
        assertEquals(Alert.CONFIDENCE_LOW, alertsRaised.get(0).getConfidence());
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
        HiddenFile hiddenFile =
                new HiddenFile(testPath, contents, Collections.emptyList(), "", links, "test_php");

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(new OkResponse("/" + testPath));

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
    public void shouldRaiseAlertWithHighConfidenceIfTestedUrlRespondsOkToCustomPayload()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "foo/test.php";
        List<String> testPaths = Arrays.asList(testPath);

        this.nano.addHandler(new OkResponse(servePath));
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
        assertEquals(Alert.CONFIDENCE_HIGH, alertsRaised.get(0).getConfidence());
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
        HiddenFile hiddenFile =
                new HiddenFile(testPath, contents, Collections.emptyList(), "", links, "test_php");

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(new NotFoundResponse("/" + testPath));

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
    public void shouldRaiseAlertIfTestedUrlRespondsOkWithRelevantContentAndAppropriateNotContent()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "CVS/root";
        List<String> contents = Arrays.asList(":");
        List<String> notContents = Arrays.asList("<");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile =
                new HiddenFile(testPath, contents, notContents, "", links, "cvs_dir");

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(
                new StaticContentServerHandler(
                        '/' + testPath,
                        ":pserver:anonymous@duma.cvs.sourceforge.net:/cvsroot/duma"));

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
        assertEquals(rule.getReference(), alert.getReference());
    }

    @Test
    public void
            shouldRaiseAlertWithLowConfidenceIfTestedUrlRespondsOkWithRelevantContentButDoesContainNotContent()
                    throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "CVS/root";
        List<String> contents = Arrays.asList(":");
        List<String> notContents = Arrays.asList("<");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile =
                new HiddenFile(testPath, contents, notContents, "", links, "cvs_dir");

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(
                new StaticContentServerHandler(
                        '/' + testPath,
                        "<html>pserver:anonymous@duma.cvs.sourceforge.net:/cvsroot/duma"));

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
        assertEquals(Alert.CONFIDENCE_LOW, alertsRaised.get(0).getConfidence());
        assertEquals(rule.getReference(), alert.getReference());
    }

    @Test
    public void shouldRaiseAlertIfTestedUrlRespondsOkWithRelevantBinContent()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = ".DS_Store";
        String validDSStoreBinString =
                new String(new byte[] {0, 0, 0, 1, 'B', 'u', 'd', '1'}, StandardCharsets.US_ASCII);
        HiddenFile hiddenFile =
                new HiddenFile(
                        testPath,
                        Collections.emptyList(),
                        Collections.emptyList(),
                        validDSStoreBinString,
                        Collections.emptyList(),
                        "ds_store");

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(new OkBinResponse('/' + testPath, validDSStoreBinString));

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
        assertEquals(rule.getReference(), alert.getReference());
    }

    @Test
    public void shouldRaiseAlertWithLowConfidenceIfTestedUrlRespondsOkWithoutRelevantBinContent()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = ".DS_Store";
        String validDSStoreBinString =
                new String(new byte[] {0, 0, 0, 1, 'B', 'u', 'd', '1'}, StandardCharsets.US_ASCII);
        String invalidDSStoreBinString =
                new String(new byte[] {0, 0, 0, 2, 'B', 'u', 'd', '2'}, StandardCharsets.US_ASCII);
        HiddenFile hiddenFile =
                new HiddenFile(
                        testPath,
                        Collections.emptyList(),
                        Collections.emptyList(),
                        validDSStoreBinString,
                        Collections.emptyList(),
                        "ds_store");

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(new OkBinResponse('/' + testPath, invalidDSStoreBinString));

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
        assertEquals(Alert.CONFIDENCE_LOW, alertsRaised.get(0).getConfidence());
        assertEquals(rule.getReference(), alert.getReference());
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

    private static class NotFoundResponse extends NanoServerHandler {

        private static final String NOT_FOUND_RESPONSE =
                "<!DOCTYPE html\">\n"
                        + "<html><head></head><H>Four oh four</H1>Not found... <html>";

        public NotFoundResponse(String path) {
            super(path);
        }

        @Override
        protected Response serve(IHTTPSession session) {
            return NanoHTTPD.newFixedLengthResponse(
                    Response.Status.NOT_FOUND, "text/html", NOT_FOUND_RESPONSE);
        }
    }

    private static class OkResponse extends StaticContentServerHandler {

        private static final String OK_RESPONSE =
                "<!DOCTYPE html\">\n" + "<html><head></head><H>Site Title</H1>Site Text... <html>";

        public OkResponse(String path) {
            super(path, OK_RESPONSE);
        }
    }

    private static class OkBinResponse extends StaticContentServerHandler {

        public OkBinResponse(String path, String content) {
            super(path, content);
        }
    }
}
