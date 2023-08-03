/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

class RelativePathConfusionScanRuleUnitTest
        extends ActiveScannerTest<RelativePathConfusionScanRule> {

    @Override
    protected RelativePathConfusionScanRule createScanner() {
        return new RelativePathConfusionScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(20)));
        assertThat(wasc, is(equalTo(20)));
        assertThat(tags.size(), is(equalTo(2)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
    }

    @Test
    void shouldNotAlertIfBaseUrlReturns404Code() throws Exception {
        // Given
        String test = "/";
        nano.addHandler(new NotFoundResponseWithReqPath(test));
        HttpMessage message = getHttpMessage(test + "sitemap.xml"); // 404 not found
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldAlertIfRelativePathConfusionIsFound() throws Exception {
        // Given
        String test = "/";
        nano.addHandler(new OkStatusResponseWithReqPath(test));
        HttpMessage message = getHttpMessage(test + "sitemap.xml"); // 200 OK
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    private static class NotFoundResponseWithReqPath extends NanoServerHandler {
        private static final String PATH_TOKEN = "@@@PATH@@@";
        private static final String NOT_FOUND_RESPONSE_WITH_REQUESTED_PATH =
                "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                        + "<html><head>\n"
                        + "<title>404 Not Found</title>\n"
                        + "</head><body>\n"
                        + "<h1>Forbidden</h1>\n"
                        + "<p>Page not found "
                        + PATH_TOKEN
                        + "\n"
                        + "on this server.</p>\n"
                        + "<a href=\"javascript:history.back()\">Return to the previous page</a>\n"
                        + "</body></html>";

        public NotFoundResponseWithReqPath(String name) {
            super(name);
        }

        @Override
        protected Response serve(IHTTPSession session) {
            return newFixedLengthResponse(
                    Response.Status.NOT_FOUND,
                    "text/html",
                    NOT_FOUND_RESPONSE_WITH_REQUESTED_PATH.replace(PATH_TOKEN, session.getUri()));
        }
    }

    private static class OkStatusResponseWithReqPath extends NanoServerHandler {
        private static final String PATH_TOKEN = "@@@PATH@@@";
        private static final String OK_STATUS_RESPONSE_WITH_REQUESTED_PATH =
                "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                        + "<html><head>\n"
                        + "<title>Title</title>\n"
                        + "</head><body>\n"
                        + "<h1>Hello! Welcome</h1>\n"
                        + PATH_TOKEN
                        + "\n"
                        + "on this server.</p>\n"
                        + "<a href=\"javascript:history.back()\">Return to the previous page</a>\n"
                        + "</body></html>";

        public OkStatusResponseWithReqPath(String name) {
            super(name);
        }

        @Override
        protected Response serve(IHTTPSession session) {
            return newFixedLengthResponse(
                    Response.Status.OK,
                    "text/html",
                    OK_STATUS_RESPONSE_WITH_REQUESTED_PATH.replace(PATH_TOKEN, session.getUri()));
        }
    }
}
