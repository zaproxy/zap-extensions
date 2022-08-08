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
import java.util.Map;
import java.util.TreeSet;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
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
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(CommonAlertTag.OWASP_2017_A07_XSS.getTag()), is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_01_REFLECTED_XSS.getTag()),
                is(equalTo(true)));
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
    void shouldReportXssInAttribute() throws NullPointerException, IOException {
        String test = "/shouldReportXssInAttribute/";

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
                        HttpRequestHeader.CONTENT_TYPE,
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
                        Response resp = newFixedLengthResponse(response);
                        return resp;
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
                        if (!StringUtils.containsIgnoreCase(name, "0W45pz4p")
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

    @Override
    protected Path getResourcePath(String resourcePath) {
        return super.getResourcePath("crosssitescriptingscanrule/" + resourcePath);
    }
}
