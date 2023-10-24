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
package org.zaproxy.addon.authhelper;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.TreeSet;
import net.htmlparser.jericho.Source;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.authhelper.AuthenticationRequestDetails.AuthDataType;
import org.zaproxy.zap.extension.anticsrf.AntiCsrfToken;
import org.zaproxy.zap.extension.anticsrf.ExtensionAntiCSRF;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.utils.Stats;

public class AuthenticationDetectionScanRule extends PluginPassiveScanner {

    private static final Logger LOGGER =
            LogManager.getLogger(AuthenticationDetectionScanRule.class);

    /**
     * A list of commonly used user parameter names. An exact (case insensitive) match on one of
     * these will be the first choice.
     */
    private static final List<String> USER_PARAMS = List.of("user", "email", "acc", "account", "u");

    /**
     * A list of commonly used user parameter name elements. A parameter which starts with one of
     * these (case insensitive) will be the second choice.
     */
    private static final List<String> USER_ELEMENTS = List.of("user", "email", "acc", "login");

    /**
     * A list of commonly used password parameter names. An exact (case insensitive) match on one of
     * these will be the first choice.
     */
    private static final List<String> PASSWORD_PARAMS = List.of("password", "pwd", "p");

    /**
     * A list of commonly used password parameter name elements. A parameter which starts with one
     * of these (case insensitive) will be the second choice.
     */
    private static final List<String> PASSWORD_ELEMENTS = List.of("pass", "pwd");

    /**
     * A list of commonly used string in authentication request URLs. A URL containing any of these
     * strings as well as a recognised user and password parameter will be treated as a high
     * confidence match.
     */
    private static final List<String> AUTH_URL_SEGMENTS =
            List.of("login", "signin", "sign-in", "inloggen", "accueil");

    /**
     * A list of commonly used string in register request URLs. A URL containing any of these
     * strings NOT be counted as an authentication request even if there are recognised user and
     * password parameters.
     */
    private static final List<String> REGISTER_URL_SEGMENTS =
            List.of("register", "signup", "sign-up");

    @Override
    public int getPluginId() {
        return 10111;
    }

    @Override
    public boolean appliesToHistoryType(int historyType) {
        return ExtensionAuthhelper.HISTORY_TYPES_SET.contains(historyType);
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        TreeSet<HtmlParameter> params;
        AuthenticationRequestDetails.AuthDataType type =
                AuthenticationRequestDetails.AuthDataType.FORM;

        if (HttpRequestHeader.POST.equals(msg.getRequestHeader().getMethod())) {
            params = msg.getFormParams();
            if (params.isEmpty()) {
                String postData = msg.getRequestBody().toString();
                if (msg.getRequestHeader().hasContentType("json")
                        && StringUtils.isNotEmpty(postData)) {
                    try {
                        try {
                            extractJsonStrings(JSONObject.fromObject(postData), "", params);
                        } catch (JSONException e) {
                            extractJsonStrings(JSONArray.fromObject(postData), "", params);
                        }
                        type = AuthenticationRequestDetails.AuthDataType.JSON;
                    } catch (JSONException e) {
                        LOGGER.debug("Unable to parse as JSON: {}", postData, e);
                    }
                }
            }
        } else {
            params = msg.getUrlParams();
        }

        HtmlParameter userParam = getMatchingParam(params, USER_PARAMS, USER_ELEMENTS);
        HtmlParameter passwordParam = getMatchingParam(params, PASSWORD_PARAMS, PASSWORD_ELEMENTS);

        if (userParam != null && passwordParam != null) {
            String urlLc = msg.getRequestHeader().getURI().toString().toLowerCase(Locale.ROOT);

            if (REGISTER_URL_SEGMENTS.stream().anyMatch(urlLc::contains)) {
                // It looks like a registration request
                LOGGER.debug("Assumed register request: {} ", msg.getRequestHeader().getURI());
                Stats.incCounter("stats.auth.detect.register");
            } else {
                // Looks like an auth request
                Stats.incCounter("stats.auth.detect.auth." + type.name().toLowerCase(Locale.ROOT));

                AuthenticationRequestDetails ard =
                        new AuthenticationRequestDetails(
                                msg.getRequestHeader().getURI(),
                                userParam,
                                passwordParam,
                                type,
                                msg.getRequestHeader().getHeader(HttpHeader.REFERER),
                                getAntiCsrfTokens(msg),
                                AUTH_URL_SEGMENTS.stream().anyMatch(urlLc::contains)
                                        ? Alert.CONFIDENCE_HIGH
                                        : Alert.CONFIDENCE_LOW);

                getAlert(ard).raise();

                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionAuthhelper.class)
                        .registerAuthRequest(ard, msg);
            }
        }
    }

    private static List<AntiCsrfToken> getAntiCsrfTokens(HttpMessage msg) {
        ExtensionAntiCSRF extAcsrf =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAntiCSRF.class);
        if (extAcsrf == null) {
            return Collections.emptyList();
        }
        return extAcsrf.getTokens(msg);
    }

    private AlertBuilder getAlert(AuthenticationRequestDetails authDetails) {
        StringBuilder sb = new StringBuilder();
        sb.append("userParam=");
        sb.append(authDetails.getUserParam().getName());
        sb.append("\nuserValue=");
        sb.append(authDetails.getUserParam().getValue());
        sb.append("\npasswordParam=");
        sb.append(authDetails.getPasswordParam().getName());
        if (!StringUtils.isEmpty(authDetails.getReferer())) {
            sb.append("\nreferer=");
            sb.append(authDetails.getReferer());
        }
        authDetails.getTokens().stream()
                .forEach(t -> sb.append("\ncsrfToken=").append(t.getName()));

        return newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(authDetails.getConfidence())
                .setParam(authDetails.getUserParam().getName())
                .setEvidence(authDetails.getPasswordParam().getName())
                .setDescription(Constant.messages.getString("authhelper.auth-detect.desc"))
                .setSolution(Constant.messages.getString("authhelper.auth-detect.soln"))
                .setReference(
                        "https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/")
                .setOtherInfo(sb.toString());
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        AuthenticationRequestDetails authDetails =
                new AuthenticationRequestDetails(
                        null,
                        new HtmlParameter(HtmlParameter.Type.form, "username", "test"),
                        new HtmlParameter(HtmlParameter.Type.form, "password", "test"),
                        AuthDataType.FORM,
                        null,
                        Collections.emptyList(),
                        0);
        alerts.add(this.getAlert(authDetails).build());
        return alerts;
    }

    private static HtmlParameter getMatchingParam(
            TreeSet<HtmlParameter> params, List<String> fullNames, List<String> elements) {
        // First try to get an exact match
        Optional<HtmlParameter> first =
                params.stream()
                        .filter(
                                i ->
                                        fullNames.stream()
                                                .anyMatch(p -> i.getName().equalsIgnoreCase(p)))
                        .findFirst();
        if (first.isPresent()) {
            return first.get();
        }
        // Next try the elements
        first =
                params.stream()
                        .filter(
                                i ->
                                        elements.stream()
                                                .anyMatch(
                                                        p ->
                                                                i.getName()
                                                                        .toLowerCase(Locale.ROOT)
                                                                        .contains(p)))
                        .findFirst();
        if (first.isPresent()) {
            return first.get();
        }
        return null;
    }

    void extractJsonStrings(JSON json, String parent, TreeSet<HtmlParameter> params) {
        if (json instanceof JSONObject) {
            JSONObject jsonObject = (JSONObject) json;
            for (Object key : jsonObject.keySet()) {
                Object obj = jsonObject.get(key);
                if (obj instanceof JSONObject) {
                    extractJsonStrings(
                            (JSONObject) obj, normalisedKey(parent, (String) key), params);
                } else if (obj instanceof String) {
                    params.add(
                            new HtmlParameter(
                                    HtmlParameter.Type.form,
                                    normalisedKey(parent, (String) key),
                                    (String) obj));
                }
            }
        } else if (json instanceof JSONArray) {
            Object[] oa = ((JSONArray) json).toArray();
            for (int i = 0; i < oa.length; i++) {
                extractJsonStrings((JSONArray) json, parent + "[" + i + "]", params);
            }
        }
    }

    private static String normalisedKey(String parent, String key) {
        return parent.isEmpty() ? key : parent + "." + key;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("authhelper.auth-detect.name");
    }
}
