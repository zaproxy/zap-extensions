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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.ascanrulesBeta.HiddenFilesScanRule.HiddenFile;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.StaticContentServerHandler;

/**
 * Unit Test for HiddenFilesScanRule.
 *
 * <p>Note: If using {@code setPayloadProvider(Supplier)} should be called before {@code
 * rule.init()}</br> Note: If using {@code addTestPayload(HiddenFile)} should be called after {@code
 * rule.init()}
 */
class HiddenFilesScanRuleUnitTest extends ActiveScannerTest<HiddenFilesScanRule> {

    private static final String NOT_FOUND_PATH = "/404.html";

    @Override
    protected HiddenFilesScanRule createScanner() {
        return new HiddenFilesScanRule();
    }

    @AfterEach
    void after() {
        HiddenFilesScanRule.setPayloadProvider(null);
    }

    @Test
    void shouldHavePayloadsFile() {
        // Given
        String filePath = "/" + HiddenFilesScanRule.PAYLOADS_FILE_PATH;
        // When
        URL url = HiddenFilesScanRule.class.getResource(filePath);
        // Then
        assertThat(url, is(notNullValue()));
    }

    @Test
    void shouldScanMessageWithoutPath() throws HttpMalformedHeaderException {
        // Given
        String path = "";
        HttpMessage msg = getHttpMessage(path);
        rule.init(msg, parent);
        HiddenFilesScanRule.addTestPayload(
                new HiddenFile(
                        "",
                        Collections.emptyList(),
                        Collections.emptyList(),
                        "",
                        Collections.emptyList(),
                        "file",
                        false));
        // When / Then
        assertDoesNotThrow(() -> rule.scan());
    }

    @Test
    void shouldSendGetRequestWhenOriginalRequestWasNotGet() throws HttpMalformedHeaderException {
        // Given
        String path = "";
        HttpMessage msg = getHttpMessage(path);
        msg.getRequestHeader().setMethod(HttpRequestHeader.POST);
        msg.getRequestHeader()
                .addHeader(HttpHeader.CONTENT_TYPE, "application/x-www-form-urlencoded");
        msg.setRequestBody("field1=value1&field2=value2");
        rule.init(msg, parent);
        HiddenFilesScanRule.addTestPayload(
                new HiddenFile(
                        "",
                        Collections.emptyList(),
                        Collections.emptyList(),
                        "",
                        Collections.emptyList(),
                        "file",
                        false));
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThanOrEqualTo(1)));
        assertEquals(HttpRequestHeader.GET, httpMessagesSent.get(0).getRequestHeader().getMethod());
        assertNull(httpMessagesSent.get(0).getRequestHeader().getHeader(HttpHeader.CONTENT_TYPE));
        assertEquals(0, httpMessagesSent.get(0).getRequestBody().length());
    }

    @Test
    void shouldRaiseAlertIfTestedUrlRespondsOkWithRelevantContent()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "foo/test.php";
        List<String> contents = Arrays.asList("Awesome");
        List<String> links = Arrays.asList("https://example.org");
        HiddenFile hiddenFile =
                new HiddenFile(
                        testPath, contents, Collections.emptyList(), "", links, "test_php", false);

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
        assertThat(httpMessagesSent, hasSize(greaterThanOrEqualTo(1)));
        assertEquals(Alert.RISK_MEDIUM, alertsRaised.get(0).getRisk());
        assertEquals(Alert.CONFIDENCE_HIGH, alertsRaised.get(0).getConfidence());
        assertEquals(hiddenFile.getType(), alert.getOtherInfo());
        assertEquals(
                rule.getReference() + '\n' + hiddenFile.getLinks().get(0), alert.getReference());
    }

    @Test
    void shouldNotRaiseAlertIfTestedUrlRespondRedirect() throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldNotAlert";

        String testPath = "foo/test.php";
        List<String> contents = Arrays.asList("Awesome");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile =
                new HiddenFile(
                        testPath, contents, Collections.emptyList(), "", links, "test_php", false);

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(new RedirectResponse("/" + testPath));

        HttpMessage msg = this.getHttpMessage(servePath);

        rule.init(msg, this.parent);
        HiddenFilesScanRule.addTestPayload(hiddenFile);
        // When
        rule.scan();
        // Then
        boolean accessed = false;
        for (HttpMessage message : httpMessagesSent) {
            if (message.getRequestHeader().getURI().toString().contains(NOT_FOUND_PATH)) {
                accessed = true;
            }
        }
        assertFalse(accessed);
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @EnumSource(names = {"LOW", "MEDIUM"})
    void shouldNotRaiseAlertIfTestedUrlRespondsForbiddenWhenThresholdNotHigh(
            AlertThreshold threshold) throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldNotAlert";

        String testPath = "foo/test.php";
        List<String> contents = Arrays.asList("Awesome");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile =
                new HiddenFile(
                        testPath, contents, Collections.emptyList(), "", links, "test_php", false);

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(new ForbiddenResponseWithReqPath("/" + testPath));

        HttpMessage msg = this.getHttpMessage(servePath);

        rule.init(msg, this.parent);
        rule.setAlertThreshold(threshold);
        HiddenFilesScanRule.addTestPayload(hiddenFile);

        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldRaiseAlertWithLowConfidenceIfTestedUrlRespondsForbiddenAtHighThreshold()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "foo/test.php";
        List<String> contents = Arrays.asList("Awesome");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile =
                new HiddenFile(
                        testPath, contents, Collections.emptyList(), "", links, "test_php", false);

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(new ForbiddenResponseWithReqPath("/" + testPath));

        HttpMessage msg = this.getHttpMessage(servePath);

        rule.init(msg, this.parent);
        rule.setAlertThreshold(AlertThreshold.HIGH);
        HiddenFilesScanRule.addTestPayload(hiddenFile);

        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(httpMessagesSent, hasSize(greaterThanOrEqualTo(1)));
        assertEquals(Alert.RISK_INFO, alertsRaised.get(0).getRisk());
        assertEquals(Alert.CONFIDENCE_LOW, alertsRaised.get(0).getConfidence());
        assertEquals(hiddenFile.getType(), alert.getOtherInfo());
    }

    @Test
    void shouldNotRaiseAlertIfPathIsntServed() throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldNotAlert";

        String testPath = "foo/test.php";
        List<String> contents = Arrays.asList("Awesome");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile =
                new HiddenFile(
                        testPath, contents, Collections.emptyList(), "", links, "test_php", false);

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(new OkResponse("/fred.php"));

        HttpMessage msg = this.getHttpMessage(servePath);

        rule.init(msg, this.parent);
        HiddenFilesScanRule.addTestPayload(hiddenFile);

        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertThat(httpMessagesSent, hasSize(greaterThanOrEqualTo(1)));
    }

    @Test
    void shouldAlertWithLowConfidenceIfContentStringsDontAllMatchAtHighThreshold()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "foo/test.php";
        List<String> contents = Arrays.asList("Site", "StringNotFound");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile =
                new HiddenFile(
                        testPath, contents, Collections.emptyList(), "", links, "test_php", false);

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(new OkResponse("/" + testPath));

        HttpMessage msg = this.getHttpMessage(servePath);

        rule.init(msg, this.parent);
        rule.setAlertThreshold(AlertThreshold.HIGH);
        HiddenFilesScanRule.addTestPayload(hiddenFile);

        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(httpMessagesSent, hasSize(greaterThanOrEqualTo(1)));
        assertEquals(Alert.RISK_MEDIUM, alertsRaised.get(0).getRisk());
        assertEquals(Alert.CONFIDENCE_LOW, alertsRaised.get(0).getConfidence());
        assertEquals(hiddenFile.getType(), alert.getOtherInfo());
        assertEquals(rule.getReference(), alert.getReference());
    }

    @ParameterizedTest
    @EnumSource(names = {"LOW", "MEDIUM"})
    void shouldNotAlertIfContentStringsDontAllMatchWhenNotHighThreshold(AlertThreshold threshold)
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "foo/test.php";
        List<String> contents = Arrays.asList("Site", "StringNotFound");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile =
                new HiddenFile(
                        testPath, contents, Collections.emptyList(), "", links, "test_php", false);

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(new OkResponse("/" + testPath));

        HttpMessage msg = this.getHttpMessage(servePath);

        rule.init(msg, this.parent);
        rule.setAlertThreshold(threshold);
        HiddenFilesScanRule.addTestPayload(hiddenFile);

        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldRaiseAlertWithHighConfidenceIfContentStringsAllMatch()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "foo/test.php";
        List<String> contents = Arrays.asList("Site", "Text");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile =
                new HiddenFile(
                        testPath, contents, Collections.emptyList(), "", links, "test_php", false);

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
        assertThat(httpMessagesSent, hasSize(greaterThanOrEqualTo(1)));
        assertEquals(Alert.RISK_MEDIUM, alertsRaised.get(0).getRisk());
        assertEquals(Alert.CONFIDENCE_HIGH, alertsRaised.get(0).getConfidence());
        assertEquals(hiddenFile.getType(), alert.getOtherInfo());
        assertEquals(rule.getReference(), alert.getReference());
    }

    @Test
    void shouldRaiseAlertWithLowConfidenceIfTestedUrlRespondsOkToCustomPayload()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "foo/test.php";
        List<String> customPaths = Arrays.asList(testPath);

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(
                new StaticContentServerHandler(
                        '/' + testPath,
                        "<html><head></head><H>Awesome Title</H1> Some Text... <html>"));

        HttpMessage msg = this.getHttpMessage(servePath);

        HiddenFilesScanRule.setPayloadProvider(() -> customPaths);
        rule.init(msg, this.parent);

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
    void shouldNotRaiseAlertIfResponseStatusIsNotOkOrAuthRelated()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldNotAlert";

        String testPath = "foo/test.php";
        List<String> contents = Arrays.asList("Site", "Text");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile =
                new HiddenFile(
                        testPath, contents, Collections.emptyList(), "", links, "test_php", false);

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(new NotFoundResponse("/" + testPath));

        HttpMessage msg = this.getHttpMessage(servePath);

        rule.init(msg, this.parent);
        HiddenFilesScanRule.addTestPayload(hiddenFile);

        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertThat(httpMessagesSent, hasSize(greaterThanOrEqualTo(1)));
    }

    @Test
    void shouldRaiseAlertIfTestedUrlRespondsOkWithRelevantContentAndAppropriateNotContent()
            throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "CVS/root";
        List<String> contents = Arrays.asList(":");
        List<String> notContents = Arrays.asList("<");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile =
                new HiddenFile(testPath, contents, notContents, "", links, "cvs_dir", false);

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
        assertThat(httpMessagesSent, hasSize(greaterThanOrEqualTo(1)));
        assertEquals(Alert.RISK_MEDIUM, alertsRaised.get(0).getRisk());
        assertEquals(Alert.CONFIDENCE_HIGH, alertsRaised.get(0).getConfidence());
        assertEquals(rule.getReference(), alert.getReference());
    }

    @Test
    void
            shouldRaiseAlertWithLowConfidenceIfTestedUrlRespondsOkWithRelevantContentButDoesContainNotContentAtHighThreshold()
                    throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "CVS/root";
        List<String> contents = Arrays.asList(":");
        List<String> notContents = Arrays.asList("<");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile =
                new HiddenFile(testPath, contents, notContents, "", links, "cvs_dir", false);

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(
                new StaticContentServerHandler(
                        '/' + testPath,
                        "<html>pserver:anonymous@duma.cvs.sourceforge.net:/cvsroot/duma"));

        HttpMessage msg = this.getHttpMessage(servePath);

        rule.init(msg, this.parent);
        rule.setAlertThreshold(AlertThreshold.HIGH);
        HiddenFilesScanRule.addTestPayload(hiddenFile);

        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(httpMessagesSent, hasSize(greaterThanOrEqualTo(1)));
        assertEquals(Alert.RISK_MEDIUM, alertsRaised.get(0).getRisk());
        assertEquals(Alert.CONFIDENCE_LOW, alertsRaised.get(0).getConfidence());
        assertEquals(rule.getReference(), alert.getReference());
    }

    @ParameterizedTest
    @EnumSource(names = {"LOW", "MEDIUM"})
    void
            shouldNotRaiseAlertIfTestedUrlRespondsOkWithRelevantContentButDoesContainNotContentWhenNotHighThreshold(
                    AlertThreshold threshold) throws HttpMalformedHeaderException {
        // Given
        String servePath = "/shouldAlert";

        String testPath = "CVS/root";
        List<String> contents = Arrays.asList(":");
        List<String> notContents = Arrays.asList("<");
        List<String> links = Collections.emptyList();
        HiddenFile hiddenFile =
                new HiddenFile(testPath, contents, notContents, "", links, "cvs_dir", false);

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(
                new StaticContentServerHandler(
                        '/' + testPath,
                        "<html>pserver:anonymous@duma.cvs.sourceforge.net:/cvsroot/duma"));

        HttpMessage msg = this.getHttpMessage(servePath);

        rule.init(msg, this.parent);
        rule.setAlertThreshold(threshold);
        HiddenFilesScanRule.addTestPayload(hiddenFile);

        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldRaiseAlertIfTestedUrlRespondsOkWithRelevantBinContent()
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
                        "ds_store",
                        false);

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
        assertThat(httpMessagesSent, hasSize(greaterThanOrEqualTo(1)));
        assertEquals(Alert.RISK_MEDIUM, alertsRaised.get(0).getRisk());
        assertEquals(Alert.CONFIDENCE_HIGH, alertsRaised.get(0).getConfidence());
        assertEquals(rule.getReference(), alert.getReference());
    }

    @Test
    void
            shouldRaiseAlertWithLowConfidenceIfTestedUrlRespondsOkWithoutRelevantBinContentAtHighThreshold()
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
                        "ds_store",
                        false);

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(new OkBinResponse('/' + testPath, invalidDSStoreBinString));

        HttpMessage msg = this.getHttpMessage(servePath);

        rule.init(msg, this.parent);
        rule.setAlertThreshold(AlertThreshold.HIGH);
        HiddenFilesScanRule.addTestPayload(hiddenFile);

        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(httpMessagesSent, hasSize(greaterThanOrEqualTo(1)));
        assertEquals(Alert.RISK_MEDIUM, alertsRaised.get(0).getRisk());
        assertEquals(Alert.CONFIDENCE_LOW, alertsRaised.get(0).getConfidence());
        assertEquals(rule.getReference(), alert.getReference());
    }

    @ParameterizedTest
    @EnumSource(names = {"LOW", "MEDIUM"})
    void shouldNotRaiseAlertIfTestedUrlRespondsOkWithoutRelevantBinContentWhenNotHighThreshold(
            AlertThreshold threshold) throws HttpMalformedHeaderException {
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
                        "ds_store",
                        false);

        this.nano.addHandler(new OkResponse(servePath));
        this.nano.addHandler(new OkBinResponse('/' + testPath, invalidDSStoreBinString));

        HttpMessage msg = this.getHttpMessage(servePath);

        rule.init(msg, this.parent);
        rule.setAlertThreshold(threshold);
        HiddenFilesScanRule.addTestPayload(hiddenFile);

        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(538)));
        assertThat(wasc, is(equalTo(13)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getValue())));
    }

    @Test
    void shouldReturnExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        Alert alert = alerts.get(0);
        Map<String, String> tags = alert.getTags();
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
        assertThat(tags.size(), is(equalTo(4)));
        assertThat(tags, hasKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()));
        assertThat(tags, hasKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()));
        assertThat(tags, hasKey(CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getTag()));
        assertThat(tags, hasKey(CommonAlertTag.CUSTOM_PAYLOADS.getTag()));
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_MEDIUM)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
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

    private static class RedirectResponse extends NanoServerHandler {

        private static final String REDIRECT_RESPONSE =
                "<!DOCTYPE html\">\n" + "<html><head></head><H>Redirecting</H1>... <html>";

        public RedirectResponse(String path) {
            super(path);
        }

        @Override
        protected Response serve(IHTTPSession session) {
            Response resp =
                    NanoHTTPD.newFixedLengthResponse(
                            Response.Status.REDIRECT, "text/html", REDIRECT_RESPONSE);
            resp.addHeader(HttpHeader.LOCATION, NOT_FOUND_PATH);
            return resp;
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
