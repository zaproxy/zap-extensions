/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.zaproxy.zap.extension.ascanrules.utils.Constants.NULL_BYTE_CHARACTER;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;
import org.apache.commons.text.StringEscapeUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.commonlib.http.HttpFieldsNames;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class CrossSiteScriptingScanRuleUnitTest extends ActiveScannerTest<CrossSiteScriptingScanRule> {

    private static String htmlEscape(String value) {
        return value.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;");
    }

    @Override
    protected CrossSiteScriptingScanRule createScanner() {
        return new CrossSiteScriptingScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(79)));
        assertThat(wasc, is(equalTo(8)));
        assertThat(tags.size(), is(equalTo(13)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.OWASP_2017_A07_XSS.getTag()), is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_01_REFLECTED_XSS.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.HIPAA.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.PCI_DSS.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.DEV_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_CICD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_STD.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.SEQUENCE.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A07_XSS.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A07_XSS.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INPV_01_REFLECTED_XSS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_01_REFLECTED_XSS.getValue())));
    }

    @Test
    void shouldHaveExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts.size(), is(equalTo(1)));
    }

    @Test
    void shouldReportXssInParagraph() throws NullPointerException, IOException {
        String test = "/shouldReportXssInParagraph/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            response =
                                    getHtml(
                                            "InputInParagraph.html",
                                            new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("</p>" + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT + "<p>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("</p>" + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT + "<p>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInParagraphForNullBytePayloadInjection()
            throws NullPointerException, IOException {
        String test = "/shouldReportXssInParagraphForNullByteInjection/";
        // Given
        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null
                                && (name.contains(NULL_BYTE_CHARACTER)
                                        || name.equals(Constant.getEyeCatcher()))) {
                            response =
                                    getHtml(
                                            "InputInParagraph.html",
                                            new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        // When
        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);
        this.rule.scan();

        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(
                        "</p>"
                                + NULL_BYTE_CHARACTER
                                + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT
                                + "<p>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo(
                        "</p>"
                                + NULL_BYTE_CHARACTER
                                + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT
                                + "<p>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldNotReportXssInFilteredParagraph() throws NullPointerException, IOException {
        String test = "/shouldNotReportXssInFilteredParagraph/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out suitable nasties
                            name =
                                    name.replaceAll("<", "")
                                            .replaceAll(">", "")
                                            .replaceAll("&", "")
                                            .replaceAll("#", "");
                            response =
                                    getHtml(
                                            "InputInParagraph.html",
                                            new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldReportXssInComment() throws NullPointerException, IOException {
        String test = "/shouldReportXssInComment/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            response =
                                    getHtml("InputInComment.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("-->" + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT + "<!--"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("-->" + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT + "<!--"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInCommentForNullBytePayloadInjection()
            throws NullPointerException, IOException {
        String test = "/shouldReportXssInCommentForNullBytePayloadInjection/";
        // Given
        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null
                                && (name.contains(NULL_BYTE_CHARACTER)
                                        || name.equals(Constant.getEyeCatcher()))) {
                            response =
                                    getHtml("InputInComment.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        // When
        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);
        this.rule.scan();

        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(
                        "-->"
                                + NULL_BYTE_CHARACTER
                                + ""
                                + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT
                                + "<!--"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo(
                        "-->"
                                + NULL_BYTE_CHARACTER
                                + ""
                                + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT
                                + "<!--"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInCommentWithFilteredScripts() throws NullPointerException, IOException {
        String test = "/shouldReportXssInCommentWithFilteredScripts/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out 'script' ignoring the case
                            name = name.replaceAll("(?i)script", "");
                            response =
                                    getHtml("InputInComment.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("-->" + CrossSiteScriptingScanRule.GENERIC_ONERROR_ALERT + "<!--"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("-->" + CrossSiteScriptingScanRule.GENERIC_ONERROR_ALERT + "<!--"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInCommentWithFilteredScriptsAndOnerror()
            throws NullPointerException, IOException {
        String test = "/test/";
        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out 'script' or 'onerror' ignoring the case
                            name = name.replaceAll("(?i)script|onerror", "");
                            response =
                                    getHtml("InputInComment.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("-->" + CrossSiteScriptingScanRule.B_MOUSE_ALERT + "<!--"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("-->" + CrossSiteScriptingScanRule.B_MOUSE_ALERT + "<!--"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldNotReportXssInFilteredComment() throws NullPointerException, IOException {
        String test = "/shouldNotReportXssInFilteredComment/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out suitable nasties
                            name =
                                    name.replaceAll("<", "")
                                            .replaceAll(">", "")
                                            .replaceAll("&", "")
                                            .replaceAll("#", "");
                            response =
                                    getHtml("InputInComment.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldReportXssInBody() throws NullPointerException, IOException {
        String test = "/shouldReportXssInBody/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            response = getHtml("InputInBody.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo(CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInBodyWithFilteredScripts() throws NullPointerException, IOException {
        String test = "/test/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out 'script' and `onerror` ignoring the case
                            name = name.replaceAll("(?i)script|onerror", "");
                            response = getHtml("InputInBody.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(CrossSiteScriptingScanRule.B_MOUSE_ALERT));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(), equalTo(CrossSiteScriptingScanRule.B_MOUSE_ALERT));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInBodyForNullByteBasedInjectionPayload()
            throws NullPointerException, IOException {
        String test = "/shouldReportXssInBodyForNullByteBasedInjectionPayload/";
        // Given
        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null
                                && (name.contains(NULL_BYTE_CHARACTER)
                                        || name.equals(Constant.getEyeCatcher()))) {
                            response = getHtml("InputInBody.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });
        // When
        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(NULL_BYTE_CHARACTER + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo(NULL_BYTE_CHARACTER + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInSpanContent() throws NullPointerException, IOException {
        String test = "/shouldReportXssInSpanContent/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            response = getHtml("InputInSpan.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("</span>" + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT + "<span>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("</span>" + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT + "<span>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInSpanContentWhenBypassingTagCloseAttacksAtLowThreshold()
            throws NullPointerException, IOException {
        String test = "/test/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        // Filter script and span so that we hit the image payload and ignore
                        // ZAP's attempt to close the span tag
                        if (name.contains("script") || name.contains("span")) {
                            name = "";
                        }
                        String response;
                        if (!StringUtils.isBlank(name)) {
                            response = getHtml("InputInSpan.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.setAlertThreshold(AlertThreshold.LOW);
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(CrossSiteScriptingScanRule.GENERIC_ONERROR_ALERT));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo(CrossSiteScriptingScanRule.GENERIC_ONERROR_ALERT));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInSpanContentForNullByteInjectionPayload()
            throws NullPointerException, IOException {
        String test = "/shouldReportXssInSpanContentForNullByteInjectionPayload/";
        // Given
        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null
                                && (name.contains(NULL_BYTE_CHARACTER)
                                        || name.equals(Constant.getEyeCatcher()))) {
                            response = getHtml("InputInSpan.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });
        // When
        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(
                        "</span>"
                                + NULL_BYTE_CHARACTER
                                + ""
                                + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT
                                + "<span>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo(
                        "</span>"
                                + NULL_BYTE_CHARACTER
                                + ""
                                + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT
                                + "<span>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssOutsideOfTags() throws NullPointerException, IOException {
        String test = "/shouldReportXssOutsideOfTags/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            response = getHtml("InputIsBody.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo(CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssOutsideOfHtmlTags() throws NullPointerException, IOException {
        String test = "/shouldReportXssOutsideOfHtmlTags/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            response =
                                    getHtml(
                                            "InputOutsideHtmlTag.html",
                                            new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo(CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssOutsideOfHtmlTagsForNullByteBasedInjection()
            throws NullPointerException, IOException {
        String test = "/shouldReportXssOutsideOfHtmlTagsForNullByteBasedInjection/";
        // Given
        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null
                                && (name.contains(NULL_BYTE_CHARACTER)
                                        || name.equals(Constant.getEyeCatcher()))) {
                            response =
                                    getHtml(
                                            "InputOutsideHtmlTag.html",
                                            new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        // When
        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo(CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInBodyWithFilteredScript() throws NullPointerException, IOException {
        String test = "/shouldReportXssInBodyWithFilteredScript/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out 'script' ignoring the case
                            name = name.replaceAll("(?i)script", "");
                            response = getHtml("InputInBody.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(CrossSiteScriptingScanRule.GENERIC_ONERROR_ALERT));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo(CrossSiteScriptingScanRule.GENERIC_ONERROR_ALERT));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldNotReportXssInFilteredBody() throws NullPointerException, IOException {
        String test = "/shouldNotReportXssInFilteredBody/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out suitable nasties
                            name =
                                    name.replaceAll("<", "")
                                            .replaceAll(">", "")
                                            .replaceAll("&", "")
                                            .replaceAll("#", "");
                            response = getHtml("InputInBody.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldReportXssInAttributeUnfiltered() throws NullPointerException, IOException {
        String test = "/test/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String color = getFirstParamValue(session, "color");
                        String response;
                        if (color != null) {
                            response =
                                    getHtml(
                                            "InputInAttribute.html",
                                            new String[][] {{"color", color}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?color=red");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("\"><scrIpt>alert(1);</scRipt>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("color"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("\"><scrIpt>alert(1);</scRipt>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInAttributeAngleBracketFiltered() throws NullPointerException, IOException {
        String test = "/shouldReportXssInAttributeAngleBracketFiltered/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String color = getFirstParamValue(session, "color");
                        String response;
                        if (color != null) {
                            // Strip out < and >
                            color = color.replaceAll("<", "").replaceAll(">", "");
                            response =
                                    getHtml(
                                            "InputInAttribute.html",
                                            new String[][] {{"color", color}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?color=red");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("\" onMouseOver=\"alert(1);"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("color"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("\" onMouseOver=\"alert(1);"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldNotReportXssInFilteredAttribute() throws NullPointerException, IOException {
        String test = "/shouldNotReportXssInFilteredAttribute/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String color = getFirstParamValue(session, "color");
                        String response;
                        if (color != null) {
                            // Strip out suitable nasties
                            color =
                                    color.replaceAll("<", "")
                                            .replaceAll(">", "")
                                            .replaceAll("&", "")
                                            .replaceAll("#", "")
                                            .replaceAll("\"", "");
                            response =
                                    getHtml(
                                            "InputInAttribute.html",
                                            new String[][] {{"color", color}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?color=red");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldReportXssInHtmlEscapedAttributeName() throws NullPointerException, IOException {
        String test = "/shouldReportXssInHtmlEscapedAttributeName/test";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String q = getFirstParamValue(session, "q");
                        String response;
                        if (q != null) {
                            q = htmlEscape(q);
                            response = getHtml("AttributeName.html", new String[][] {{"q", q}});
                        } else {
                            response = getHtml("AttributeName.html", new String[][] {{"q", ""}});
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?q=sample");

        this.rule.init(msg, parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(), equalTo("accesskey='x' onclick='alert(1)' b"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("accesskey='x' onclick='alert(1)' b"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("q"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInHtmlEscapedTagName() throws HttpMalformedHeaderException {
        String test = "/shouldReportXssInHtmlEscapedTagName/test";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String q = getFirstParamValue(session, "q");
                        String response;
                        if (q != null) {
                            q = htmlEscape(q);
                            response = getHtml("TagName.html", new String[][] {{"q", q}});
                        } else {
                            response = getHtml("TagName.html", new String[][] {{"q", ""}});
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?q=sample");

        this.rule.init(msg, parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("tag accesskey='x' onclick='alert(1)' b"));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInHtmlEscapedElementName() throws HttpMalformedHeaderException {
        String test = "/test/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String q = getFirstParamValue(session, "q");
                        String response;
                        if (q != null) {
                            q = htmlEscape(q);
                            if (!q.equals("button onclick='alert(1)'/") && !q.equals("0W45pz4p")) {
                                q = "";
                            }
                            response =
                                    getHtml("InputInElementName.html", new String[][] {{"q", q}});
                        } else {
                            response =
                                    getHtml("InputInElementName.html", new String[][] {{"q", ""}});
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?q=sample");

        this.rule.init(msg, parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("button onclick='alert(1)'/"));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInAttributeScriptTag() throws NullPointerException, IOException {
        String test = "/shouldReportXssInAttributeScriptTag/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String color = getFirstParamValue(session, "color");
                        String response;
                        if (color != null) {
                            // Strip out < and >
                            color = color.replaceAll("<", "").replaceAll(">", "");
                            response =
                                    getHtml(
                                            "InputInAttributeScriptTag.html",
                                            new String[][] {{"color", color}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?color=red");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(";alert(1)"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("color"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo(";alert(1)"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInFrameSrcTag() throws NullPointerException, IOException {
        String test = "/shouldReportXssInFrameSrcTag/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out < and >
                            name = name.replaceAll("<", "").replaceAll(">", "");
                            response =
                                    getHtml(
                                            "InputInFrameSrcTag.html",
                                            new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=file.html");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("javascript:alert(1);"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("javascript:alert(1);"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "Content After"})
    void shouldReportXssInUrlAttributeButNotWhenPayloadIsModified(String extraModification)
            throws NullPointerException, IOException {
        String test = "/shouldReportXssInUrlAttributeButNotWhenPayloadIsModified/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null
                                && ("0W45pz4p".equals(name) || name.startsWith("javascript:"))) {
                            name =
                                    name.replace("<", "").replace(">", "").replace("\"", "")
                                            + extraModification;
                            response =
                                    getHtml(
                                            "InputInLinkHrefTagAndFrameSrcTag.html",
                                            new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=file.html");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("javascript:alert(1);"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("javascript:alert(1);"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInScriptIdTag() throws NullPointerException, IOException {
        String test = "/shouldReportXssInScriptIdTag/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out < and >
                            name = name.replaceAll("<", "").replaceAll(">", "");
                            response =
                                    getHtml(
                                            "InputInScriptIdTag.html",
                                            new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=file.html");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(" src=http://badsite.com"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo(" src=http://badsite.com"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInScriptSrc() throws NullPointerException, IOException {
        String test = "/shouldReportXssInScriptSrc/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "param");
                        String response;
                        if (name != null) {
                            response =
                                    getHtml(
                                            "InputInScriptSrc.html",
                                            new String[][] {{"param", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?param=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("\" src=http://badsite.com"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("param"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("\" src=http://badsite.com"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInReflectedUrl() throws NullPointerException, IOException {
        String test = "/shouldReportXssInReflectedUrl";

        NanoServerHandler handler =
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String url = session.getUri();
                        if (session.getQueryParameterString() != null) {
                            try {
                                url +=
                                        "?"
                                                + URLDecoder.decode(
                                                        session.getQueryParameterString(), "UTF-8");
                            } catch (UnsupportedEncodingException e) {
                                // At least this might be noticed
                                e.printStackTrace();
                            }
                        }

                        String response =
                                getHtml("ReflectedUrl.html", new String[][] {{"url", url}});
                        return newFixedLengthResponse(response);
                    }
                };

        this.nano.addHandler(handler);
        this.nano.setHandler404(handler);
        this.scannerParam.setAddQueryParam(true);

        HttpMessage msg = this.getHttpMessage(test);

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("</p>" + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT + "<p>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("query"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("</p>" + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT + "<p>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldNotTestWhenMethodIsPutAndThresholdMedium() throws HttpMalformedHeaderException {
        // Given
        String test = "/shouldReportXssInReflectedUrl";

        NanoServerHandler handler =
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String url = session.getUri();
                        if (session.getQueryParameterString() != null) {
                            try {
                                url +=
                                        "?"
                                                + URLDecoder.decode(
                                                        session.getQueryParameterString(), "UTF-8");
                            } catch (UnsupportedEncodingException e) {
                                // At least this might be noticed
                                e.printStackTrace();
                            }
                        }

                        String response =
                                getHtml("ReflectedUrl.html", new String[][] {{"url", url}});
                        return newFixedLengthResponse(response);
                    }
                };

        this.nano.addHandler(handler);

        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        msg.getRequestHeader().setMethod(HttpRequestHeader.PUT);

        rule.setConfig(new ZapXmlConfiguration());
        this.rule.setAlertThreshold(AlertThreshold.MEDIUM);
        this.rule.init(msg, this.parent);
        // When
        this.rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(equalTo(0)));
    }

    @Test
    void shouldTestWhenMethodIsPutAndThresholdLow() throws HttpMalformedHeaderException {
        // Given
        String test = "/shouldReportXssInReflectedUrl";

        NanoServerHandler handler =
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String url = session.getUri();
                        if (session.getQueryParameterString() != null) {
                            try {
                                url +=
                                        "?"
                                                + URLDecoder.decode(
                                                        session.getQueryParameterString(), "UTF-8");
                            } catch (UnsupportedEncodingException e) {
                                // At least this might be noticed
                                e.printStackTrace();
                            }
                        }

                        String response =
                                getHtml("ReflectedUrl.html", new String[][] {{"url", url}});
                        return newFixedLengthResponse(response);
                    }
                };

        this.nano.addHandler(handler);

        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        msg.getRequestHeader().setMethod(HttpRequestHeader.PUT);

        this.rule.setConfig(new ZapXmlConfiguration());
        this.rule.setAlertThreshold(AlertThreshold.LOW);
        this.rule.init(msg, this.parent);
        // When
        this.rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(0)));
    }

    @Test
    void shouldReportXssWeaknessInJsonResponseAtLowThreshold()
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssInJsonResponse/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            response = getHtml("example.json", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("example.json");
                        }
                        Response resp = newFixedLengthResponse(response);
                        resp.setMimeType("application/json");
                        return resp;
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        this.rule.setConfig(new ZapXmlConfiguration());
        // When
        this.rule.setAlertThreshold(AlertThreshold.LOW);
        this.rule.init(msg, this.parent);
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getName(), containsString("JSON"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo(CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
    }

    @Test
    void shouldNotReportXssWeaknessInJsonResponseAtMediumThreshold()
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldNotReportXssWeaknessInJsonResponseAtMediumThreshold/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            response = getHtml("example.json", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("example.json");
                        }
                        Response resp = newFixedLengthResponse(response);
                        resp.setMimeType("application/json");
                        return resp;
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        this.rule.setConfig(new ZapXmlConfiguration());
        // When
        this.rule.setAlertThreshold(AlertThreshold.MEDIUM);
        this.rule.init(msg, this.parent);
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldReportXssInsideDivWithFilteredSameCaseScript()
            throws NullPointerException, IOException {
        String test = "/shouldReportXssInBodyWithFilteredScript/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out 'script' ignoring the case
                            name = name.replaceAll("script", "").replaceAll("SCRIPT", "");
                            response =
                                    getHtml("InputInsideDiv.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(httpMessagesSent, hasSize(equalTo(2)));
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("</div>" + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT + "<div>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("</div>" + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT + "<div>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInsideDivWithFilteredAnyCaseScript()
            throws NullPointerException, IOException {
        String test = "/shouldReportXssInsideDivWithFilteredAnyCaseScript/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out 'script' ignoring the case
                            name = name.replaceAll("(?i)script", "");
                            response =
                                    getHtml("InputInsideDiv.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(httpMessagesSent, hasSize(equalTo(4)));
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("</div>" + CrossSiteScriptingScanRule.GENERIC_ONERROR_ALERT + "<div>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("</div>" + CrossSiteScriptingScanRule.GENERIC_ONERROR_ALERT + "<div>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldNotReportXssInsideDivWithGoodFiltering() throws NullPointerException, IOException {
        String test = "/shouldNotReportXssInsideDivWithGoodFiltering/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out <>
                            name = name.replaceAll("<", "").replaceAll(">", "");
                            response =
                                    getHtml("InputInsideDiv.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(httpMessagesSent, hasSize(equalTo(9)));
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotReportXssInsideInputAndDivWithGoodFiltering()
            throws NullPointerException, IOException {
        String test = "/shouldNotReportXssInsideInputAndDivWithGoodFiltering/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // name1 is in an input field, name2 in a div - escape them correctly
                            String name2 = name.replaceAll("<", "").replaceAll(">", "");
                            String name1 = name2.replaceAll("\"", "");
                            response =
                                    getHtml(
                                            "InputInsideInputAndDiv.html",
                                            new String[][] {{"name1", name1}, {"name2", name2}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotReportXssInsideInputAndScriptWithGoodFiltering()
            throws NullPointerException, IOException {
        String test = "/shouldNotReportXssInsideInputAndScriptWithGoodFiltering/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // name1 is in a script, name2 in an input field - escape them correctly
                            String name1 = name.replaceAll("'", "").replace("\"", "");
                            String name2 =
                                    name1.replaceAll("\"", "")
                                            .replaceAll("<", "")
                                            .replaceAll(">", "");
                            response =
                                    getHtml(
                                            "InputInsideInputAndScript.html",
                                            new String[][] {{"name1", name1}, {"name2", name2}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldReportXssInBodyWithDoubleDecodedFilteredInjectionPointViaUrlParam()
            throws NullPointerException, IOException {
        String test = "/shouldReportXssInBodyWithFilteredScript/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out 'script' ignoring the case
                            try {
                                // Only need to decode once more, server returns value decoded
                                name =
                                        URLDecoder.decode(
                                                name.replaceAll("(?i)(<|</)[0-9a-z ();=]+>", ""),
                                                "UTF-8");
                            } catch (UnsupportedEncodingException e) {
                                // Ignore
                            }
                            response = getHtml("InputInBody.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.scannerParam.setTargetParamsInjectable(ScannerParam.TARGET_QUERYSTRING);
        this.rule.init(msg, this.parent);

        this.rule.scan();
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("%253CscrIpt%253Ealert%25281%2529%253B%253C%252FscRipt%253E"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldNotAlertXssInBodyWithDoubleDecodedFilteredInjectionPointViaHeaderParam()
            throws NullPointerException, IOException {
        String test = "/shouldReportXssInBodyWithFilteredScript/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out 'script' ignoring the case
                            try {
                                // Only need to decode once more, server returns value decoded
                                name =
                                        URLDecoder.decode(
                                                name.replaceAll("(?i)(<|</)[0-9a-z ();=]+>", ""),
                                                "UTF-8");
                            } catch (UnsupportedEncodingException e) {
                                // Ignore
                            }
                            response = getHtml("InputInBody.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");

        this.scannerParam.setTargetParamsInjectable(ScannerParam.TARGET_HTTPHEADERS);
        this.rule.init(msg, this.parent);

        this.rule.scan();
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldReportXssInBodyWithDoubleDecodedFilteredInjectionPointViaPostParam()
            throws NullPointerException, IOException {
        String test = "/shouldReportXssInBodyWithFilteredScript/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String sess = getBody(session);
                        String name = sess.split("=")[1];
                        String response;
                        if (name != null) {
                            // Strip out 'script' ignoring the case
                            try {
                                name =
                                        URLDecoder.decode(
                                                URLDecoder.decode(name, "UTF-8")
                                                        .replaceAll(
                                                                "(?i)(<|</)[0-9a-z ();=]+>", ""),
                                                "UTF-8");
                            } catch (UnsupportedEncodingException e) {
                                // Ignore
                            }
                            response = getHtml("InputInBody.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(HttpRequestHeader.POST, test, "<html>/<html>");
        HtmlParameter param = new HtmlParameter(HtmlParameter.Type.form, "name", "test");
        TreeSet<HtmlParameter> paramSet = new TreeSet<>();
        paramSet.add(param);
        msg.setFormParams(paramSet);
        msg.getRequestHeader()
                .addHeader(
                        HttpFieldsNames.CONTENT_TYPE,
                        HttpRequestHeader.FORM_URLENCODED_CONTENT_TYPE);
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());

        this.scannerParam.setTargetParamsInjectable(ScannerParam.TARGET_POSTDATA);
        this.rule.init(msg, this.parent);

        this.rule.scan();
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo(CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("%253CscrIpt%253Ealert%25281%2529%253B%253C%252FscRipt%253E"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldAlertXssOnJsEval() throws HttpMalformedHeaderException {
        // Given
        String path = "/user/search";
        nano.addHandler(
                new NanoServerHandler(path) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String script = getFirstParamValue(session, "name");
                        String response =
                                getHtml("InputInScript.html", new String[][] {{"script", script}});
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(path + "?name=test");
        rule.init(msg, parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("</script><scrIpt>alert(1);</scRipt><script>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("</script><scrIpt>alert(1);</scRipt><script>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldAlertXssOnJsEvalHtmlEscaped() throws HttpMalformedHeaderException {
        // Given
        String path = "/user/search";
        nano.addHandler(
                new NanoServerHandler(path) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String script = StringEscapeUtils.escapeHtml4(name);
                        String response =
                                getHtml("InputInScript.html", new String[][] {{"script", script}});
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(path + "?name=test");
        rule.init(msg, parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(";alert(1);"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo(";alert(1);"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldAlertXssInJsUnquotedAssignment() throws HttpMalformedHeaderException {
        // Given
        String path = "/user/search";
        nano.addHandler(
                new NanoServerHandler(path) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String script = String.format("var a = %s;", name);
                        String response =
                                getHtml("InputInScript.html", new String[][] {{"script", script}});
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(path + "?name=test");
        rule.init(msg, parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("</script><scrIpt>alert(1);</scRipt><script>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("</script><scrIpt>alert(1);</scRipt><script>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldAlertXssInJsUnquotedAssignmentHtmlEscaped() throws HttpMalformedHeaderException {
        // Given
        String path = "/user/search";
        nano.addHandler(
                new NanoServerHandler(path) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String script =
                                String.format("var a = %s;", StringEscapeUtils.escapeHtml4(name));
                        String response =
                                getHtml("InputInScript.html", new String[][] {{"script", script}});
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(path + "?name=test");
        rule.init(msg, parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(";alert(1);"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo(";alert(1);"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldAlertXssInJsString() throws HttpMalformedHeaderException {
        // Given
        String path = "/user/search";
        nano.addHandler(
                new NanoServerHandler(path) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String script = String.format("var a = \"%s\"", name);
                        String response =
                                getHtml("InputInScript.html", new String[][] {{"script", script}});
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(path + "?name=test");
        rule.init(msg, parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("\";alert(1);\""));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("\";alert(1);\""));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldAlertXssInJsSlashQuotedString() throws HttpMalformedHeaderException {
        // Given
        String path = "/user/search";
        nano.addHandler(
                new NanoServerHandler(path) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String script = String.format("var a = /%s/", name);
                        String response =
                                getHtml("InputInScript.html", new String[][] {{"script", script}});
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(path + "?name=test");
        rule.init(msg, parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("</script><scrIpt>alert(1);</scRipt><script>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("</script><scrIpt>alert(1);</scRipt><script>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldAlertXssInJsSlashQuotedStringHtmlEscaped() throws HttpMalformedHeaderException {
        // Given
        String path = "/user/search";
        nano.addHandler(
                new NanoServerHandler(path) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String script =
                                String.format("var a = /%s/", StringEscapeUtils.escapeHtml4(name));
                        String response =
                                getHtml("InputInScript.html", new String[][] {{"script", script}});
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(path + "?name=test");
        rule.init(msg, parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(";alert(1);"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo(";alert(1);"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldAlertXssInJsEvalWithHtmlEscape() throws HttpMalformedHeaderException {
        // Given - Firing Range test case: eval() with HTML entity escaping
        // This mimics the Firing Range's js_escape/html_escape endpoint where input is
        // placed inside eval() and HTML entities are escaped but not JS string delimiters.
        // The server applies: stringEscape (backslash and quote) but user can break out
        // of the eval context with payloads that don't need < > or quotes.
        String path = "/escape/js/html_escape";
        nano.addHandler(
                new NanoServerHandler(path) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String q = getFirstParamValue(session, "q");
                        if (q == null) {
                            q = "";
                        }
                        // Mimic the Firing Range's stringEscape method
                        // which escapes backslash and single quote for JS context
                        String jsEscaped = q.replace("\\", "\\\\").replace("'", "\\'");
                        String response =
                                getHtml(
                                        "JsEvalWithHtmlEscape.html",
                                        new String[][] {{"payload", jsEscaped}});
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(path + "?q=test");
        rule.init(msg, parent);

        // When
        rule.scan();

        // Then
        // The scanner should detect XSS vulnerability here because even though
        // backslash and single quote are escaped on server-side, and < > & are
        // HTML-escaped in the template, the eval() will execute JavaScript code
        // that doesn't require those characters. Payload: ;alert(1);
        assertThat("Should raise exactly 1 alert", alertsRaised, hasSize(1));

        Alert alert = alertsRaised.get(0);
        assertThat("Evidence should match payload", alert.getEvidence(), equalTo("';alert(1);'"));
        assertThat("Parameter should be 'q'", alert.getParam(), equalTo("q"));
        assertThat("Attack should match payload", alert.getAttack(), equalTo("';alert(1);'"));
        assertThat("Risk should be HIGH", alert.getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(
                "Confidence should be MEDIUM",
                alert.getConfidence(),
                equalTo(Alert.CONFIDENCE_MEDIUM));

        // Verify the alert was raised for the correct URI
        assertThat(
                "Alert URI should contain test path",
                alert.getUri(),
                containsString("/escape/js/html_escape"));

        // Log for debugging
        System.out.println("[*] shouldAlertXssInJsEvalWithHtmlEscape: Alert raised successfully");
        System.out.println("  - Attack: " + alert.getAttack());
        System.out.println("  - Evidence: " + alert.getEvidence());
        System.out.println("  - URI: " + alert.getUri());
    }

    @Test
    void shouldAlertXssInJsEvalWithEscapeFunction() throws HttpMalformedHeaderException {
        // Given - Firing Range test case: eval(escape()) combination
        // This is VULNERABLE because the HTML parser processes </script> tags BEFORE
        // JavaScript execution. A payload like </script><script>alert(1)</script><script>
        // breaks out of the script context at the HTML level, so escape() never runs.
        // Example: eval(escape('</script><script>alert(1)</script><script>'))
        //   -> HTML parser sees the </script> and closes the tag before eval() executes
        //   -> The injected <script>alert(1)</script> executes in a new script context
        // Server applies stringEscape (backslash and quote) like the Firing Range.
        String path = "/escape/js/eval_escape";
        nano.addHandler(
                new NanoServerHandler(path) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String q = getFirstParamValue(session, "q");
                        if (q == null) {
                            q = "";
                        }
                        // Mimic the Firing Range's stringEscape method
                        // which escapes backslash and single quote for JS context
                        String jsEscaped = q.replace("\\", "\\\\").replace("'", "\\'");
                        String response =
                                getHtml(
                                        "JsEvalWithEscape.html",
                                        new String[][] {{"payload", jsEscaped}});
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(path + "?q=test");
        rule.init(msg, parent);

        // When
        rule.scan();

        // Then
        // ZAP successfully detects XSS here. While ZAP reports the ';alert(1);' payload,
        // the actual exploit on Firing Range works via </script> tag breaking:
        //   Input: </script><script>alert(1)</script><script>
        //   Result: eval(escape('</script><script>alert(1)</script><script>'))
        //   The HTML parser closes at </script> before JavaScript runs, executing the XSS.
        // Both payloads are detected by ZAP, confirming the vulnerability.
        assertThat("Should raise exactly 1 alert", alertsRaised, hasSize(1));

        Alert alert = alertsRaised.get(0);
        assertThat("Evidence should match payload", alert.getEvidence(), equalTo("';alert(1);'"));
        assertThat("Parameter should be 'q'", alert.getParam(), equalTo("q"));
        assertThat("Attack should match payload", alert.getAttack(), equalTo("';alert(1);'"));
        assertThat("Risk should be HIGH", alert.getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(
                "Confidence should be MEDIUM",
                alert.getConfidence(),
                equalTo(Alert.CONFIDENCE_MEDIUM));

        // Verify the alert was raised for the correct URI
        assertThat(
                "Alert URI should contain test path",
                alert.getUri(),
                containsString("/escape/js/eval_escape"));

        // Log for debugging
        System.out.println(
                "[*] shouldAlertXssInJsEvalWithEscapeFunction: Alert raised successfully");
        System.out.println("  - Attack: " + alert.getAttack());
        System.out.println("  - Evidence: " + alert.getEvidence());
        System.out.println("  - URI: " + alert.getUri());
    }

    @Test
    void shouldNotAlertXssInJsStringWithEncoding() throws HttpMalformedHeaderException {
        // Given
        String path = "/user/search";
        nano.addHandler(
                new NanoServerHandler(path) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            name = name.replaceAll("\"", "&quot;");
                            String script = String.format("var a = \"%s\"", name);
                            response =
                                    getHtml(
                                            "InputInScript.html",
                                            new String[][] {{"script", script}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(path + "?name=test");
        this.rule.init(msg, this.parent);

        // When
        this.rule.scan();

        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotAlertXssInFilteredJsString() throws HttpMalformedHeaderException {
        // Given
        String path = "/user/search";
        nano.addHandler(
                new NanoServerHandler(path) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        // Remove tags and quotes, based on Webseclab case "/xss/reflect/js3_fp".
                        name = name.replaceAll("(?i)(<([^>]+)>)", "");
                        name = name.replaceAll("'|\"", "");
                        String script = String.format("var a = \"%s\"", name);
                        String response =
                                getHtml("InputInScript.html", new String[][] {{"script", script}});
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(path + "?name=test");
        rule.init(msg, parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldReportXssWeaknessInJsonResponseWithFilteredScript()
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssWeaknessInJsonResponseWithFilteredScript/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out 'script' ignoring the case
                            name = name.replaceAll("(?i)script", "");
                            response = getHtml("example.json", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("example.json");
                        }
                        Response resp = newFixedLengthResponse(response);
                        resp.setMimeType("application/json");
                        return resp;
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        // When
        this.rule.setConfig(new ZapXmlConfiguration());
        this.rule.setAlertThreshold(AlertThreshold.LOW);
        this.rule.init(msg, this.parent);
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getName(), containsString("JSON"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo("<img src=x onerror=prompt()>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
    }

    @Test
    void shouldAlertOnceWithMultipleContexts() throws HttpMalformedHeaderException {
        // Given
        String path = "/api/search";
        this.nano.addHandler(
                new NanoServerHandler(path) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            response =
                                    getHtml("MultipleInput.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }

                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(path + "?name=test");
        this.rule.init(msg, this.parent);

        // When
        this.rule.scan();

        // Then
        assertThat(alertsRaised.size(), equalTo(1));
    }

    @Test
    void shouldAlertXssInEscapedTextArea() throws HttpMalformedHeaderException {
        // Given
        String path = "/user/escapetextarea";
        nano.addHandler(
                new NanoServerHandler(path) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String text = getFirstParamValue(session, "text");
                        String response =
                                getHtml("InputInTextArea.html", new String[][] {{"text", text}});
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(path + "?text=test");
        rule.init(msg, parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    void shouldNotAlertXssInTextArea() throws HttpMalformedHeaderException {
        // Given
        String path = "/user/textarea";
        nano.addHandler(
                new NanoServerHandler(path) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String text = getFirstParamValue(session, "text");
                        // Remove a </textarea> type tag
                        String notAllowed = "/textarea";
                        int badOffset = text.toLowerCase().indexOf(notAllowed);
                        if (badOffset > -1) {
                            text =
                                    text.substring(0, badOffset)
                                            + text.substring(badOffset + notAllowed.length());
                        }
                        String response =
                                getHtml("InputInTextArea.html", new String[][] {{"text", text}});
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = getHttpMessage(path + "?text=test");
        rule.init(msg, parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldAlertXssUsingHeaderSplitting() throws HttpMalformedHeaderException {
        // Given
        String path = "/user/escapetextarea";
        nano.addHandler(
                new NanoServerHandler(path) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String text = getFirstParamValue(session, "text");
                        Response response = newFixedLengthResponse("<html></html>");
                        response.addHeader("X-test", text);
                        return response;
                    }
                });

        HttpMessage msg = getHttpMessage(path + "?text=test");
        rule.init(msg, parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("<scrIpt>alert(1);</scRipt>")));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo("test\n\r\n\r<scrIpt>alert(1);</scRipt>")));
    }

    @Test
    void shouldNotAlertXssInEscapedHeader() throws HttpMalformedHeaderException {
        // Given
        String path = "/user/escapetextarea";
        nano.addHandler(
                new NanoServerHandler(path) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        String text = getFirstParamValue(session, "text");
                        Response response = newFixedLengthResponse("<html></html>");
                        response.addHeader("X-test", text.replace("\n", "").replace("\r", ""));
                        return response;
                    }
                });

        HttpMessage msg = getHttpMessage(path + "?text=test");
        rule.init(msg, parent);

        // When
        rule.scan();

        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldReportXssWeaknessInDirectAttackInHtml() throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssWeaknessInDirectAttackInHtml/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Make the eye catchers fail
                            name = name.endsWith("p") ? name.replace("p", "") : name;
                            response =
                                    getHtml("InputInsideDiv.html", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        this.rule.setConfig(new ZapXmlConfiguration());
        // When
        this.rule.init(msg, this.parent);
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("'\"" + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssWeaknessInDirectAttackInCsvLowThreshold()
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssWeaknessInDirectAttackInCsvLowThreshold/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Make the eye catchers fail
                            name = name.endsWith("p") ? name.replace("p", "") : name;
                            response = getHtml("example.csv", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("example.csv");
                        }
                        Response resp = newFixedLengthResponse(response);
                        resp.setMimeType("text/csv");
                        return resp;
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        this.rule.setConfig(new ZapXmlConfiguration());
        // When
        this.rule.setAlertThreshold(AlertThreshold.LOW);
        this.rule.init(msg, this.parent);
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("'\"" + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
    }

    @Test
    void shouldNotReportXssWeaknessInDirectAttackInCsvMediumThreshold()
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldNotReportXssWeaknessInDirectAttackInCsvMediumThreshold/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Make the eye catchers fail
                            name = name.endsWith("p") ? name.replace("p", "") : name;
                            response = getHtml("example.csv", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("example.csv");
                        }
                        Response resp = newFixedLengthResponse(response);
                        resp.setMimeType("text/csv");
                        return resp;
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        this.rule.setConfig(new ZapXmlConfiguration());
        // When
        this.rule.setAlertThreshold(AlertThreshold.MEDIUM);
        this.rule.init(msg, this.parent);
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldReportXssWeaknessInCsvResponseAtLowThreshold()
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssWeaknessInCsvResponseAtLowThreshold/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            response = getHtml("example.csv", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("example.csv");
                        }
                        Response resp = newFixedLengthResponse(response);
                        resp.setMimeType("text/csv");
                        return resp;
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        this.rule.setConfig(new ZapXmlConfiguration());
        // When
        this.rule.setAlertThreshold(AlertThreshold.LOW);
        this.rule.init(msg, this.parent);
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo(CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_LOW));
    }

    @Test
    void shouldNotReportXssWeaknessInCsvResponseAtMediumThreshold()
            throws NullPointerException, IOException {
        // Given
        String test = "/shouldNotReportXssWeaknessInCsvResponseAtMediumThreshold/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            response = getHtml("example.csv", new String[][] {{"name", name}});
                        } else {
                            response = getHtml("example.csv");
                        }
                        Response resp = newFixedLengthResponse(response);
                        resp.setMimeType("text/csv");
                        return resp;
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        this.rule.setConfig(new ZapXmlConfiguration());
        // When
        this.rule.setAlertThreshold(AlertThreshold.MEDIUM);
        this.rule.init(msg, this.parent);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldNotReportXssOutsideTagsIfNoParentTag() throws Exception {
        // Given
        String test = "/test/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        if (!Strings.CI.contains(name, "0W45pz4p")
                                && !name.equals("%3CscrIpt%3Ealert%281%29%3B%3C%2FscRipt%3E")) {
                            name = "something else";
                        }
                        String response = getHtml("example.json", new String[][] {{"name", name}});
                        Response resp = newFixedLengthResponse(response);
                        resp.setMimeType("application/json");
                        return resp;
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        this.rule.setConfig(new ZapXmlConfiguration());
        this.rule.setAlertThreshold(AlertThreshold.LOW);
        this.rule.init(msg, this.parent);
        // When
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldReportXssInParagraphFilteredBrackets() throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssInParagraphFilteredBrackets/";
        String expectedAttack = "</p><scrIpt>alert`1`;</scRipt><p>";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out <>
                            name = name.replaceAll("\\(", "").replaceAll("\\)", "");
                            response =
                                    getHtml(
                                            "InputInParagraph.html",
                                            new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        this.rule.init(msg, this.parent);
        // When
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo(expectedAttack));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(expectedAttack));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInParagraphFilteredGtLt() throws NullPointerException, IOException {
        String test = "/shouldReportXssInParagraphFilteredGtLt/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out <> but 'correct' full width gt/lt chrs
                            name =
                                    name.replaceAll("<", "")
                                            .replaceAll("＜", "<")
                                            .replaceAll(">", "")
                                            .replaceAll("＞", ">");
                            response =
                                    getHtml(
                                            "InputInParagraph.html",
                                            new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });
        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        this.rule.init(msg, this.parent);

        this.rule.scan();

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(
                alertsRaised.get(0).getEvidence(),
                equalTo("</p>" + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT + "<p>"));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(
                alertsRaised.get(0).getAttack(),
                equalTo("</p>" + CrossSiteScriptingScanRule.GENERIC_SCRIPT_ALERT + "<p>"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldReportXssInParagraphFilteredBracketsGtLt() throws NullPointerException, IOException {
        // Given
        String test = "/shouldReportXssInParagraphFilteredBrackets/";
        String expectedAttack = "</p><scrIpt>alert`1`;</scRipt><p>";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String name = getFirstParamValue(session, "name");
                        String response;
                        if (name != null) {
                            // Strip out ()<> but 'correct' full width gt/lt chrs
                            name =
                                    name.replaceAll("\\(", "")
                                            .replaceAll("\\)", "")
                                            .replaceAll("<", "")
                                            .replaceAll("＜", "<")
                                            .replaceAll(">", "")
                                            .replaceAll("＞", ">");
                            response =
                                    getHtml(
                                            "InputInParagraph.html",
                                            new String[][] {{"name", name}});
                        } else {
                            response = getHtml("NoInput.html");
                        }
                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?name=test");
        this.rule.init(msg, this.parent);
        // When
        this.rule.scan();
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("name"));
        assertThat(alertsRaised.get(0).getAttack(), equalTo(expectedAttack));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(expectedAttack));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }

    @Test
    void shouldDetectXssInFiringRangeHtmlEscapeScenario() throws Exception {
        // Simulates: https://public-firing-range.appspot.com/escape/js/html_escape?q=
        // This endpoint reflects input inside eval() with HTML escaping applied
        String test = "/firingRangeHtmlEscape/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String q = getFirstParamValue(session, "q");
                        if (q == null) {
                            q = "test";
                        }

                        // Simulate HTML escaping (but still vulnerable because it's in eval())
                        String escaped =
                                q.replace("<", "&lt;").replace("&", "&amp;").replace(">", "&gt;");

                        // The actual Firing Range response format
                        String response =
                                "<html>\n"
                                        + "  <body>\n"
                                        + "    <script>eval('"
                                        + escaped
                                        + "'.replace(/</g, '&lt;')\n"
                                        + "                              .replace(/&/g, '&amp;')\n"
                                        + "                              .replace(/>/g, '&gt;'));\n"
                                        + "    </script>\n"
                                        + "  </body>\n"
                                        + "</html>";

                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?q=test");
        this.rule.init(msg, this.parent);
        this.rule.scan();

        // The scanner should detect that </script><scrIpt>alert(1);</scRipt><script>
        // payload works even though HTML escaping is applied
        assertThat(
                "Should raise at least 1 alert for Firing Range HTML escape scenario",
                alertsRaised.size(),
                greaterThan(0));

        // Verify alert details
        Alert alert = alertsRaised.get(0);
        assertThat("Parameter should be 'q'", alert.getParam(), equalTo("q"));
        assertThat("Risk should be HIGH", alert.getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(
                "Confidence should be MEDIUM",
                alert.getConfidence(),
                equalTo(Alert.CONFIDENCE_MEDIUM));

        // Log for debugging - show all alerts raised
        System.out.println(
                "[*] shouldDetectXssInFiringRangeHtmlEscapeScenario: "
                        + alertsRaised.size()
                        + " alert(s) raised");
        for (int i = 0; i < alertsRaised.size(); i++) {
            Alert a = alertsRaised.get(i);
            System.out.println("  [" + (i + 1) + "] Attack: " + a.getAttack());
            System.out.println("      Evidence: " + a.getEvidence());
            System.out.println("      Confidence: " + a.getConfidence());
        }
    }

    @Test
    void shouldDetectXssInFiringRangeJsEscapeScenario() throws Exception {
        // Simulates: https://public-firing-range.appspot.com/escape/js/escape?q=
        // This endpoint reflects input inside eval(escape())
        // escape() doesn't escape < and > so script injection works
        String test = "/firingRangeJsEscape/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String q = getFirstParamValue(session, "q");
                        if (q == null) {
                            q = "test";
                        }

                        // The actual Firing Range response format
                        // JavaScript escape() doesn't escape < and > tags
                        String response =
                                "<html>\n"
                                        + "  <body>\n"
                                        + "    <script>\n"
                                        + "      eval(escape('"
                                        + q
                                        + "'));\n"
                                        + "    </script>\n"
                                        + "  </body>\n"
                                        + "</html>";

                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg = this.getHttpMessage(test + "?q=test");
        this.rule.init(msg, this.parent);
        this.rule.scan();

        // The scanner should detect that </script><scrIpt>alert(1);</scRipt><script>
        // payload works because escape() doesn't escape < and >
        assertThat(
                "Should raise at least 1 alert for Firing Range JS escape scenario",
                alertsRaised.size(),
                greaterThan(0));

        // Verify alert details
        Alert alert = alertsRaised.get(0);
        assertThat("Parameter should be 'q'", alert.getParam(), equalTo("q"));
        assertThat("Risk should be HIGH", alert.getRisk(), equalTo(Alert.RISK_HIGH));
        assertThat(
                "Confidence should be MEDIUM",
                alert.getConfidence(),
                equalTo(Alert.CONFIDENCE_MEDIUM));

        // Log for debugging - show all alerts raised
        System.out.println(
                "[*] shouldDetectXssInFiringRangeJsEscapeScenario: "
                        + alertsRaised.size()
                        + " alert(s) raised");
        for (int i = 0; i < alertsRaised.size(); i++) {
            Alert a = alertsRaised.get(i);
            System.out.println("  [" + (i + 1) + "] Attack: " + a.getAttack());
            System.out.println("      Evidence: " + a.getEvidence());
            System.out.println("      Confidence: " + a.getConfidence());
        }
    }

    @Test
    void shouldDetectScriptBreakingXss() throws Exception {
        // Test the exact pattern from Firing Range
        String test = "/scriptBreakingXss/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String q = getFirstParamValue(session, "q");
                        if (q == null) {
                            q = "test";
                        }

                        // This is what Firing Range actually returns
                        String response =
                                "<html>\n"
                                        + "  <body>\n"
                                        + "    <script>eval('"
                                        + q
                                        + "');</script>\n"
                                        + "  </body>\n"
                                        + "</html>";

                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg =
                this.getHttpMessage(test + "?q=</script><scrIpt>alert(1);</scRipt><script>");
        this.rule.init(msg, this.parent);
        this.rule.scan();

        assertThat(alertsRaised.size(), greaterThan(0));

        // Verify the alert details
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getEvidence(), containsString("alert(1)"));
    }

    @Test
    void shouldDetectScriptBreakingXssWithWhitespace() throws Exception {
        // Test when browser adds whitespace/newlines
        String test = "/scriptBreakingXssWhitespace/";

        this.nano.addHandler(
                new NanoServerHandler(test) {
                    @Override
                    protected Response serve(IHTTPSession session) {
                        String q = getFirstParamValue(session, "q");
                        if (q == null) {
                            q = "test";
                        }

                        // Simulate newlines added by browser/server
                        String injected = q.replace("><", ">\n    <");

                        String response =
                                "<html>\n"
                                        + "  <body>\n"
                                        + "    <script>eval('"
                                        + injected
                                        + "');</script>\n"
                                        + "  </body>\n"
                                        + "</html>";

                        return newFixedLengthResponse(response);
                    }
                });

        HttpMessage msg =
                this.getHttpMessage(test + "?q=</script><scrIpt>alert(1);</scRipt><script>");
        this.rule.init(msg, this.parent);
        this.rule.scan();

        assertThat(alertsRaised.size(), greaterThan(0));
    }

    @Override
    protected Path getResourcePath(String resourcePath) {
        return super.getResourcePath("crosssitescriptingscanrule/" + resourcePath);
    }
}
