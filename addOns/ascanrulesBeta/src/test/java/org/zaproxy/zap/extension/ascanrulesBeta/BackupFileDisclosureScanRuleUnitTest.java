/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link BackupFileDisclosureScanRule}. */
class BackupFileDisclosureScanRuleUnitTest extends ActiveScannerTest<BackupFileDisclosureScanRule> {

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
    private static final String URL = "/dir/index.html";

    @Override
    protected BackupFileDisclosureScanRule createScanner() {
        BackupFileDisclosureScanRule rule = new BackupFileDisclosureScanRule();
        rule.setConfig(new ZapXmlConfiguration());
        return rule;
    }

    @Override
    protected HttpMessage getHttpMessageForSendReasonableNumberOfMessages(String defaultPath)
            throws HttpMalformedHeaderException {
        return super.getHttpMessageForSendReasonableNumberOfMessages(URL);
    }

    @Test
    void shouldNotAlertIfNonExistingBackupFileReturnsNon404Code() throws Exception {
        // Given
        String test = "/";
        nano.addHandler(new ForbiddenResponseWithReqPath(test));
        HttpMessage message = getHttpMessage(test + "sitemap.xml"); // 200 OK
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfOriginalFileNorBackupReturnsNon200Code() throws Exception {
        // Given
        String test = "/";
        nano.addHandler(new ForbiddenResponseWithReqPath(test));
        HttpMessage message = getHttpMessage(test + "sitemap.xml");
        message.setResponseHeader("HTTP/1.1 403 Forbidden\r\n");
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldAlertIfBackupResponseIsNotEmptyAndIsDifferentStatusFromBogusRequest()
            throws Exception {
        // Given
        String test = "/";
        nano.addHandler(
                new NanoServerHandler(test) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        boolean isAlertUrl = session.getUri().contains("sitemap.xml.bak");
                        String content = isAlertUrl ? "<html></html>" : "";
                        Response.Status rs =
                                isAlertUrl ? Response.Status.OK : Response.Status.NOT_FOUND;
                        return newFixedLengthResponse(rs, NanoHTTPD.MIME_HTML, content);
                    }
                });
        HttpMessage message = getHttpMessage(test + "sitemap.xml");
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @ParameterizedTest
    @ValueSource(ints = {301, 403, 500})
    void shouldNotAlertIfBackupResponseIsNonSuccessStdThreshold(int status) throws Exception {
        // Given
        String test = "/";
        nano.addHandler(
                new NanoServerHandler(test) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        boolean isAlertUrl = session.getUri().contains("sitemap.xml.bak");
                        String content = isAlertUrl ? "<html></html>" : "";
                        Response.Status rs =
                                isAlertUrl
                                        ? Response.Status.lookup(status)
                                        : Response.Status.NOT_FOUND;
                        return newFixedLengthResponse(rs, NanoHTTPD.MIME_HTML, content);
                    }
                });
        HttpMessage message = getHttpMessage(test + "sitemap.xml");
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @ValueSource(ints = {301, 403, 500})
    void shouldAlertIfBackupResponseIsNonSuccessLowThreshold(int status) throws Exception {
        // Given
        String test = "/";
        nano.addHandler(
                new NanoServerHandler(test) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        boolean isAlertUrl = session.getUri().contains("sitemap.xml.bak");
                        String content = isAlertUrl ? "<html></html>" : "";
                        Response.Status rs =
                                isAlertUrl
                                        ? Response.Status.lookup(status)
                                        : Response.Status.NOT_FOUND;
                        return newFixedLengthResponse(rs, NanoHTTPD.MIME_HTML, content);
                    }
                });
        HttpMessage message = getHttpMessage(test + "sitemap.xml");
        rule.init(message, parent);
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @ParameterizedTest
    @ValueSource(ints = {301, 403, 500})
    void shouldAlertIfOldBackupResponseAfterNonSuccess(int status) throws Exception {
        // Given
        String test = "/";
        nano.addHandler(
                new NanoServerHandler(test) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        boolean isAlertUrl = session.getUri().contains("sitemap.xml.old");
                        String content = isAlertUrl ? "<html></html>" : "";
                        Response.Status rs;
                        if (isAlertUrl) {
                            rs = Response.Status.OK;
                        } else if (session.getUri().contains("sitemap.xml.bak")) {
                            rs = Response.Status.lookup(status);
                        } else {
                            rs = Response.Status.NOT_FOUND;
                        }
                        return newFixedLengthResponse(rs, NanoHTTPD.MIME_HTML, content);
                    }
                });
        HttpMessage message = getHttpMessage(test + "sitemap.xml");
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldAlertIfBackupDir() throws Exception {
        // Given
        String test = "/dirbackup/";
        nano.addHandler(
                new NanoServerHandler(test) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        boolean isAlertUrl =
                                session.getUri().contains("dirbackup/index.html")
                                        || session.getUri().contains("dirbackup/sitemap.xml");
                        String content = isAlertUrl ? "<html></html>" : "";
                        Response.Status rs =
                                isAlertUrl ? Response.Status.OK : Response.Status.NOT_FOUND;
                        return newFixedLengthResponse(rs, NanoHTTPD.MIME_HTML, content);
                    }
                });
        HttpMessage message = getHttpMessage("/dir/sitemap.xml");
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @ParameterizedTest
    @ValueSource(ints = {301, 403, 500})
    void shouldNotAlertIfBackupDirResponseIsNonSuccessStdThreshold(int status) throws Exception {
        // Given
        String test = "/dirbackup/";
        nano.addHandler(
                new NanoServerHandler(test) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        boolean isAlertUrl = session.getUri().contains("sitemap.xml");
                        String content = isAlertUrl ? "<html></html>" : "";
                        Response.Status rs =
                                isAlertUrl
                                        ? Response.Status.lookup(status)
                                        : Response.Status.NOT_FOUND;
                        return newFixedLengthResponse(rs, NanoHTTPD.MIME_HTML, content);
                    }
                });
        HttpMessage message = getHttpMessage("/dir/sitemap.xml");
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @ValueSource(ints = {301, 403, 500})
    void shouldAlertIfBackupDirResponseIsNonSuccessLowThreshold(int status) throws Exception {
        // Given
        String test = "/dirbackup/";
        nano.addHandler(
                new NanoServerHandler(test) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        boolean isAlertUrl = session.getUri().contains("sitemap.xml");
                        String content = isAlertUrl ? "<html></html>" : "";
                        Response.Status rs =
                                isAlertUrl
                                        ? Response.Status.lookup(status)
                                        : Response.Status.NOT_FOUND;
                        return newFixedLengthResponse(rs, NanoHTTPD.MIME_HTML, content);
                    }
                });
        HttpMessage message = getHttpMessage("/dir/sitemap.xml");
        rule.init(message, parent);
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(530)));
        assertThat(wasc, is(equalTo(34)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CONF_04_BACKUP_FILES.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_CONF_04_BACKUP_FILES.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_CONF_04_BACKUP_FILES.getValue())));
    }

    @Test
    void shouldHaveExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
        Alert alert = alerts.get(0);
        assertThat(alert.getAttack(), is(equalTo("https://example.com/profile.asp.old")));
        assertThat(
                alert.getOtherInfo(),
                is(
                        equalTo(
                                "A backup of [https://example.com/profile.asp] is available at"
                                        + " [https://example.com/profile.asp.old]")));
    }

    @Test
    @Override
    public void shouldHaveValidReferences() {
        super.shouldHaveValidReferences();
    }

    private static class ForbiddenResponseWithReqPath extends NanoServerHandler {

        public ForbiddenResponseWithReqPath(String name) {
            super(name);
        }

        @Override
        protected Response serve(IHTTPSession session) {
            return newFixedLengthResponse(
                    Response.Status.FORBIDDEN,
                    "text/html",
                    FORBIDDEN_RESPONSE_WITH_REQUESTED_PATH.replace(PATH_TOKEN, session.getUri()));
        }
    }
}
