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
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrulesBeta;

import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertThat;

import org.junit.Test;
import org.parosproxy.paros.network.HttpMessage;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;

/**
 * Unit test for {@link BackupFileDisclosure}.
 */
public class BackupFileDisclosureUnitTest extends ActiveScannerTest<BackupFileDisclosure> {

    private static final String PATH_TOKEN = "@@@PATH@@@";
    private static final String FORBIDDEN_RESPONSE_WITH_REQUESTED_PATH =
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
            + "<html><head>\n"
            + "<title>403 Forbidden</title>\n"
            + "</head><body>\n"
            + "<h1>Forbidden</h1>\n"
            + "<p>You don't have permission to access " + PATH_TOKEN + "\n"
            + "on this server.</p>\n"
            + "</body></html>";

    @Override
    protected BackupFileDisclosure createScanner() {
        return new BackupFileDisclosure();
    }

    @Test
    public void shouldNotAlertIfNonExistingBackupFileReturnsNon404Code() throws Exception {
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
    public void shouldNotAlertIfOriginalFileNorBackupReturnsNon200Code() throws Exception {
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

    private static class ForbiddenResponseWithReqPath extends NanoServerHandler {

        public ForbiddenResponseWithReqPath(String name) {
            super(name);
        }

        @Override
        protected Response serve(IHTTPSession session) {
            return new Response(
                    Response.Status.FORBIDDEN,
                    "text/html",
                    FORBIDDEN_RESPONSE_WITH_REQUESTED_PATH.replace(PATH_TOKEN, session.getUri()));
        }
    }
}
