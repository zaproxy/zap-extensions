/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import fi.iki.elonen.NanoHTTPD;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.addon.oast.OastPayload;
import org.zaproxy.addon.oast.OastService;
import org.zaproxy.zap.testutils.NanoServerHandler;

class SsrfScanRuleUnitTest extends ActiveScannerTest<SsrfScanRule> {

    private ExtensionOast extensionOast;
    private String nanoHost;

    @Override
    protected SsrfScanRule createScanner() {
        return new SsrfScanRule();
    }

    @BeforeEach
    void init() throws Exception {
        nano.addHandler(new TargetServerHandler());
        nano.addHandler(new StaticOastServerHandler());
        nanoHost = "localhost:" + nano.getListeningPort();
        HttpMessage httpMessageToTest = getHttpMessage("/path?url=https://" + nanoHost + "/path2");

        extensionOast = mock(ExtensionOast.class);
        Control.initSingletonForTesting(Model.getSingleton(), mock(ExtensionLoader.class));
        when(Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class))
                .thenReturn(extensionOast);

        rule.init(httpMessageToTest, parent);
    }

    @Test
    void shouldRaiseAlertIfCanaryInResponse() throws Exception {
        // Given
        when(extensionOast.getActiveScanOastService()).thenReturn(mock(OastService.class));
        when(extensionOast.registerAlertAndGetOastPayload(any()))
                .thenReturn(new OastPayload(nanoHost + "/12345", "54321"));
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    private static class StaticOastServerHandler extends NanoServerHandler {
        public StaticOastServerHandler() {
            super("/12345");
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            return newFixedLengthResponse("54321");
        }
    }

    private static class TargetServerHandler extends NanoServerHandler {
        public TargetServerHandler() {
            super("/path");
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            try {
                if ("/path".equals(session.getUri())) {
                    String url = getFirstParamValue(session, "url");
                    HttpSender sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);
                    HttpMessage msg = new HttpMessage(new URI(url, true));
                    sender.sendAndReceive(msg);
                    return newFixedLengthResponse(
                            "Response from " + url + " was: " + msg.getResponseBody().toString());
                } else if ("/path2".equals(session.getUri())) {
                    return newFixedLengthResponse("This is the body for /path2.");
                }
            } catch (Exception e) {
                return newFixedLengthResponse(
                        NanoHTTPD.Response.Status.INTERNAL_ERROR,
                        NanoHTTPD.MIME_PLAINTEXT,
                        "Something went wrong.");
            }
            return newFixedLengthResponse(
                    NanoHTTPD.Response.Status.NOT_FOUND, NanoHTTPD.MIME_PLAINTEXT, "Not found.");
        }
    }
}
