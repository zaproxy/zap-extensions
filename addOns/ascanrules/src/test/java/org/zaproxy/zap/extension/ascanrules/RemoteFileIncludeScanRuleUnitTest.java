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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.zaproxy.zap.extension.ascanrules.utils.Constants.NULL_BYTE_CHARACTER;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/** Unit test for {@link RemoteFileIncludeScanRule}. */
class RemoteFileIncludeScanRuleUnitTest extends ActiveScannerTest<RemoteFileIncludeScanRule> {

    @Override
    protected RemoteFileIncludeScanRule createScanner() {
        RemoteFileIncludeScanRule scanner = new RemoteFileIncludeScanRule();
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
        assertThat(cwe, is(equalTo(98)));
        assertThat(wasc, is(equalTo(5)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_11_CODE_INJ.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A01_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INPV_11_CODE_INJ.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_11_CODE_INJ.getValue())));
    }

    @Test
    void shouldRaiseAlertIfResponseHasRemoteFileContentAndPayloadIsNullByteBased()
            throws HttpMalformedHeaderException {
        // Given
        NullByteVulnerableServerHandler vulnServerHandler =
                new NullByteVulnerableServerHandler("/", "p", Tech.Linux) {
                    @Override
                    protected String getContent(IHTTPSession session) {
                        String value = getFirstParamValue(session, "p");
                        if (value.contains(NULL_BYTE_CHARACTER)) {
                            return "<html><title>Google</title></html>";
                        } else {
                            return "<html></html>";
                        }
                    }
                };
        nano.addHandler(vulnServerHandler);
        rule.init(getHttpMessage("/?p=a"), parent);
        rule.setAttackStrength(AttackStrength.INSANE);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldRaiseAlertIfResponseHasRemoteFileContent() throws HttpMalformedHeaderException {
        // Given
        this.nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        String file = getFirstParamValue(session, "file");
                        if (file != null && file.length() > 1) {
                            Response response =
                                    newFixedLengthResponse(
                                            NanoHTTPD.Response.Status.OK,
                                            NanoHTTPD.MIME_HTML,
                                            "<html><title>Google</title></html>");
                            return response;
                        }
                        String response = "<html><body></body></html>";
                        return newFixedLengthResponse(response);
                    }
                });
        rule.init(getHttpMessage("/?file=a"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldNotRaiseAlertIfResponseIsRedirectWithoutRemoteFileContent()
            throws HttpMalformedHeaderException {
        // Given
        this.nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        String file = getFirstParamValue(session, "file");
                        if (file != null && file.length() > 1) {
                            Response response =
                                    newFixedLengthResponse(
                                            NanoHTTPD.Response.Status.REDIRECT,
                                            NanoHTTPD.MIME_HTML,
                                            "<html><title>Redirecting</title></html>");
                            response.addHeader(HttpHeader.LOCATION, file);
                            return response;
                        }
                        String response = "<html><body></body></html>";
                        return newFixedLengthResponse(response);
                    }
                });
        rule.init(getHttpMessage("/?file=a"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotRaiseAlertIfResponseIsOkWithoutRemoteFileContent()
            throws HttpMalformedHeaderException {
        // Given
        this.nano.addHandler(
                new NanoServerHandler("/") {
                    @Override
                    protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
                        String file = getFirstParamValue(session, "file");
                        if (file != null && file.length() > 1) {
                            Response response =
                                    newFixedLengthResponse(
                                            NanoHTTPD.Response.Status.OK,
                                            NanoHTTPD.MIME_HTML,
                                            "<html><title>Fred's Place</title></html>");
                            return response;
                        }
                        String response = "<html><body></body></html>";
                        return newFixedLengthResponse(response);
                    }
                });
        rule.init(getHttpMessage("/?file=a"), parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }
}
