/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * A scan rule to detect Same Origin Method Execution (SOME)
 * https://www.blackhat.com/docs/eu-14/materials/eu-14-Hayak-Same-Origin-Method-Execution-Exploiting-A-Callback-For-Same-Origin-Policy-Bypass-wp.pdf
 *
 * @author Karthik UJ (@5up3r541y4n)
 */
public class SameOriginMethodExecutionScanRule extends PluginPassiveScanner {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanalpha.some.";

    private static final int PLUGIN_ID = 10114;
    private static final Pattern JSONP_PATTERN =
            Pattern.compile("([\\w$\\.]+?)\\(.*?\\)", Pattern.CASE_INSENSITIVE);
    private static final ArrayList<String> CALLBACK_PARAMS =
            new ArrayList<String>() {
                {
                    add("callback");
                    add("target");
                    add("cb");
                    add("jsonp");
                    add("cmd");
                    add("readyFunction");
                    add("jsoncallback");
                }
            };
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN,
                    CommonAlertTag.OWASP_2017_A03_DATA_EXPOSED);

    private static final Logger LOGGER =
            LogManager.getLogger(SameOriginMethodExecutionScanRule.class);

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        String respBody = msg.getResponseBody().toString();
        TreeSet<HtmlParameter> allUrlParameters = getUrlParameters(msg);
        List<Element> scriptTags = source.getAllElements(HTMLElementName.SCRIPT);
        String sfdHeader = msg.getRequestHeader().getHeader("Sec-Fetch-Dest");
        String refererHeader = msg.getRequestHeader().getHeader(HttpHeader.REFERER);

        // Method 1: Heuristics check on <script> tag.
        performHeuristicsCheck(allUrlParameters, scriptTags, msg);

        // Method 2: Check JSONP endpoint
        performJsonpEndpointCheck(msg, sfdHeader, respBody, allUrlParameters, refererHeader);
    }

    private AlertBuilder createAlert(String type, int confidence, String evidence, String param) {
        return newAlert()
                .setParam(param)
                .setRisk(Alert.RISK_HIGH)
                .setConfidence(confidence)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "desc"))
                .setOtherInfo(
                        Constant.messages.getString(MESSAGE_PREFIX + type + ".extrainfo", param))
                .setReference(
                        "https://www.benhayak.com/2015/06/same-origin-method-execution-some.html")
                .setEvidence(evidence)
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "soln"))
                .setCweId(359) // CWE-359: Exposure of Private Information ('Privacy Violation')
                .setWascId(13); // WASC-13: Information Leakage
    }

    private void performHeuristicsCheck(
            TreeSet<HtmlParameter> allUrlParameters, List<Element> scriptTags, HttpMessage msg) {

        if (msg.getResponseHeader().isHtml()) {
            for (HtmlParameter param : allUrlParameters) {
                if (param.getValue().isEmpty()) {
                    continue;
                }

                if (CALLBACK_PARAMS.contains(param.getName())
                        && msg.getRequestHeader().getURI().toString().contains(".swf")) {
                    createAlert("swf", Alert.CONFIDENCE_MEDIUM, param.getName(), param.getName())
                            .raise();
                }

                for (Element tag : scriptTags) {
                    String src = tag.getAttributeValue("src");
                    for (String callbackParam : CALLBACK_PARAMS) {
                        String expectedUrlParam = callbackParam + "=" + param.getValue();

                        if (src.contains(expectedUrlParam)) {
                            createAlert(
                                            "heuristics",
                                            Alert.CONFIDENCE_MEDIUM,
                                            expectedUrlParam,
                                            param.getName())
                                    .raise();
                        }
                    }
                }
            }
        }
    }

    private void performJsonpEndpointCheck(
            HttpMessage msg,
            String sfdHeader,
            String respBody,
            TreeSet<HtmlParameter> allUrlParameters,
            String refererHeader) {
        if (!msg.getResponseHeader().isJson()
                || !msg.getRequestHeader().getMethod().equals(HttpRequestHeader.GET)
                || !(msg.getResponseHeader().getStatusCode() == HttpStatusCode.OK)
                || !(sfdHeader == null || sfdHeader.equals("script"))
                || respBody.startsWith("jquery")) {
            return;
        }

        try {
            JSONObject.fromObject(respBody);
            return;
        } catch (JSONException e) {
            // If execution reaches here it means that the response body was not valid JSON,
            // which is likely to be the case in JSONP responses.
        }

        for (HtmlParameter param : allUrlParameters) {
            Matcher funcMatcher = JSONP_PATTERN.matcher(respBody);
            while (funcMatcher.find()) {
                String matchedFuncName = funcMatcher.group(1);
                if (matchedFuncName.equals(param.getValue())) {
                    createAlert(
                                    "jsonp",
                                    (sfdHeader != null && sfdHeader.equals("script"))
                                            ? Alert.CONFIDENCE_HIGH
                                            : Alert.CONFIDENCE_MEDIUM,
                                    param.getValue(),
                                    refererHeader)
                            .raise();
                }
            }
        }
    }

    private TreeSet<HtmlParameter> getUrlParameters(HttpMessage newReq) {
        try {
            newReq.getRequestHeader()
                    .setURI(
                            new URI(
                                    URLDecoder.decode(
                                            newReq.getRequestHeader().getURI().toString(),
                                            StandardCharsets.UTF_8.toString()),
                                    true));
        } catch (URIException | UnsupportedEncodingException e) {
            LOGGER.debug(e.getMessage());
        }

        return newReq.getUrlParams();
    }

    public String getHelpLink() {
        return "https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules-alpha/#same-origin-method-execution";
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        return List.of(
                createAlert(
                                "jsonp",
                                Alert.CONFIDENCE_MEDIUM,
                                "callbackFunc",
                                "https://www.example.com/")
                        .build());
    }
}
