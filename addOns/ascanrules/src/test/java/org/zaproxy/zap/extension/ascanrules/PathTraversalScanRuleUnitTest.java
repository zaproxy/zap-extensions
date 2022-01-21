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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Map;
import org.apache.commons.lang.ArrayUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link PathTraversalScanRule}. */
class PathTraversalScanRuleUnitTest extends ActiveScannerTest<PathTraversalScanRule> {

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(AttackStrength strength) {
        int recommendMax = super.getRecommendMaxNumberMessagesPerParam(strength);
        switch (strength) {
            case LOW:
                return recommendMax + 4;
            case MEDIUM:
            default:
                return recommendMax + 6;
            case HIGH:
                return recommendMax + 7;
            case INSANE:
                return recommendMax + 9;
        }
    }

    @Override
    protected PathTraversalScanRule createScanner() {
        PathTraversalScanRule scanner = new PathTraversalScanRule();
        scanner.setConfig(new ZapXmlConfiguration());
        return scanner;
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(22)));
        assertThat(wasc, is(equalTo(33)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_ATHZ_01_DIR_TRAVERSAL.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A01_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A05_BROKEN_AC.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_ATHZ_01_DIR_TRAVERSAL.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_ATHZ_01_DIR_TRAVERSAL.getValue())));
    }

    @Test
    void shouldNotAlertIfAttackResponseDoesNotListDirectories() throws Exception {
        // Given
        rule.init(getHttpMessage("/?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldAlertIfAttackResponseListsWindowsDirectories() throws Exception {
        // Given
        nano.addHandler(new ListWinDirsOnAttack("/", "p", "c:/"));
        rule.init(getHttpMessage("/?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("Windows")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("p")));
        assertThat(alertsRaised.get(0).getAttack(), is(equalTo("c:/")));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo("Check 3")));
    }

    @Test
    void shouldAlertIfAttackResponseListsLinuxDirectories() throws Exception {
        // Given
        nano.addHandler(new ListLinuxDirsOnAttack("/", "p", "/"));
        rule.init(getHttpMessage("/?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("etc")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("p")));
        assertThat(alertsRaised.get(0).getAttack(), is(equalTo("/")));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo("Check 3")));
    }

    @Test
    void shouldNotAlertIfAttackResponseListsBogusLinuxDirectories() throws Exception {
        // Given
        nano.addHandler(new ListBogusLinuxDirsOnAttack("/", "p", "/"));
        rule.init(getHttpMessage("/?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfLocalFilePathTraversalDoesNotExist() throws Exception {
        // Given
        nano.addHandler(new LocalFileHandler("/", "p", ""));
        rule.init(getHttpMessage("/?p"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfOriginalResponseAlreadyContainsTheEvidence() throws Exception {
        // Given
        String filePath = "/static-file";
        String fileContent = ListWinDirsOnAttack.DIRS_LISTING;
        nano.addHandler(
                new NanoServerHandler(filePath) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        return newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, fileContent);
                    }
                });
        rule.init(getHttpMessage("GET", filePath, fileContent), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldRaiseAlertIfResponseHasPasswdFileContentAndPayloadIsNullByteBased()
            throws HttpMalformedHeaderException {
        // Given
        NullByteVulnerableServerHandler vulnServerHandler =
                new NullByteVulnerableServerHandler("/", "p", Tech.Linux);
        nano.addHandler(vulnServerHandler);
        rule.init(getHttpMessage("/?p=a"), parent);
        rule.setAttackStrength(AttackStrength.INSANE);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo("Check 2")));
    }

    @Test
    void shouldRaiseAlertIfResponseHasSystemINIFileContentAndPayloadIsNullByteBased()
            throws HttpMalformedHeaderException {
        // Given
        NullByteVulnerableServerHandler vulnServerHandler =
                new NullByteVulnerableServerHandler("/", "p", Tech.Windows);
        nano.addHandler(vulnServerHandler);
        rule.init(getHttpMessage("/?p=a"), parent);
        rule.setAttackStrength(AttackStrength.INSANE);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo("Check 1")));
    }

    @ParameterizedTest
    @EnumSource(
            value = Plugin.AlertThreshold.class,
            names = {"LOW", "MEDIUM"})
    void shouldAlertOnCheckFiveBelowHighThresholdUnderValidConditions(AlertThreshold alertThreshold)
            throws HttpMalformedHeaderException {
        // Given
        String path = "/file.ext";
        HttpMessage msg = getHttpMessage(path + "?p=a");
        rule.init(msg, parent);
        nano.addHandler(new Check5Handler(path, "p", Check5Handler.GENERIC_CONTENT, true));
        rule.setAlertThreshold(alertThreshold);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo("Check 5")));
    }

    @Test
    void shouldNotAlertOnCheckFiveAtHighThresholdUnderValidConditions()
            throws HttpMalformedHeaderException {
        // Given
        String path = "/file.ext";
        HttpMessage msg = getHttpMessage(path + "?p=a");
        rule.init(msg, parent);
        nano.addHandler(new Check5Handler(path, "p", Check5Handler.GENERIC_CONTENT, true));
        rule.setAlertThreshold(AlertThreshold.HIGH);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertOnCheckFiveAtLowThresholdUnderInvalidInitialConditions()
            throws HttpMalformedHeaderException {
        // Given
        String path = "/file.ext";
        HttpMessage msg = getHttpMessage(path + "?p=a");
        rule.init(msg, parent);
        nano.addHandler(new Check5Handler(path, "p", Check5Handler.GENERIC_CONTENT, false));
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @ValueSource(strings = {"error", "Error"})
    void shouldNotAlertOnCheckFiveAtLowThresholdUnderInvalidConditions(String errorText)
            throws HttpMalformedHeaderException {
        // Given
        String path = "/file.ext";
        HttpMessage msg = getHttpMessage(path + "?p=a");
        rule.init(msg, parent);
        nano.addHandler(new Check5Handler(path, "p", errorText, true));
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    private abstract static class ListDirsOnAttack extends NanoServerHandler {

        private final String param;
        private final String attack;

        public ListDirsOnAttack(String path, String param, String attack) {
            super(path);

            this.param = param;
            this.attack = attack;
        }

        protected abstract String getDirs();

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (attack.equals(value)) {
                return newFixedLengthResponse(Response.Status.OK, NanoHTTPD.MIME_HTML, getDirs());
            }
            return newFixedLengthResponse(
                    Response.Status.NOT_FOUND, NanoHTTPD.MIME_HTML, "404 Not Found");
        }
    }

    private static class ListWinDirsOnAttack extends ListDirsOnAttack {

        private static final String DIRS_LISTING =
                "<td><a href=\"Windows/\">Windows</a></td>"
                        + "<td><a href=\"Program Files/\">Program Files</a></td>";

        public ListWinDirsOnAttack(String path, String param, String attack) {
            super(path, param, attack);
        }

        @Override
        protected String getDirs() {
            return DIRS_LISTING;
        }
    }

    private static class ListLinuxDirsOnAttack extends ListDirsOnAttack {

        private static final String DIRS_LISTING =
                "<td><a href=\"/bin/\">bin</a></td>"
                        + "<td><a href=\"/etc/\">etc</a></td>"
                        + "<td><a href=\"/boot/\">boot</a></td>";

        public ListLinuxDirsOnAttack(String path, String param, String attack) {
            super(path, param, attack);
        }

        @Override
        protected String getDirs() {
            return DIRS_LISTING;
        }
    }

    private static class ListBogusLinuxDirsOnAttack extends ListDirsOnAttack {

        private static final String DIRS_LISTING =
                "<td><a href=\"/bin/\">bin</a></td>"
                        + "<td><a href=\"/getChoice/\">getChoice</a></td>" // Matches etc but isn't
                        // etc
                        + "<td><a href=\"/boot/\">boot</a></td>";

        public ListBogusLinuxDirsOnAttack(String path, String param, String attack) {
            super(path, param, attack);
        }

        @Override
        protected String getDirs() {
            return DIRS_LISTING;
        }
    }

    private static class LocalFileHandler extends NanoServerHandler {

        private final String param;
        private final String[] existingFiles;

        public LocalFileHandler(String path, String param, String... existingFiles) {
            super(path);

            this.param = param;
            this.existingFiles = existingFiles;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (ArrayUtils.contains(existingFiles, value)) {
                return newFixedLengthResponse(
                        Response.Status.OK, NanoHTTPD.MIME_HTML, "File Found");
            }
            return newFixedLengthResponse(
                    Response.Status.NOT_FOUND, NanoHTTPD.MIME_HTML, "404 Not Found");
        }
    }

    private static class Check5Handler extends NanoServerHandler {
        private static final String GENERIC_CONTENT = "<HTML>Some Generic Content</HTML>";

        private final String param;
        private final String content;
        private final boolean passInitialCheck;

        public Check5Handler(String path, String param, String content, boolean passInitialCheck) {
            super(path);
            this.param = param;
            this.content = content;
            this.passInitialCheck = passInitialCheck;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (value.equals("thishouldnotexistandhopefullyitwillnot") && passInitialCheck) {
                return newFixedLengthResponse("Error");
            }
            return newFixedLengthResponse(content);
        }
    }
}
