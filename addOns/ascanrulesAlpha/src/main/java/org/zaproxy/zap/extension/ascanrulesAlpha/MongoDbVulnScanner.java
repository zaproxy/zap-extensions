/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.json.JSONException;
import org.json.JSONObject;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.*;
import org.zaproxy.zap.authentication.FormBasedAuthenticationMethodType;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.model.Context;

/*
 * A ZAP extension which scans for mongo db vulnerabilities.
 */
public class MongoDbVulnScanner extends AbstractAppParamPlugin {

    private static final int PLUGIN_ID = 40016;
    private static final String MESSAGE_PREFIX = "ascanrules.mongodbvuln.";

    private static Logger log = Logger.getLogger(MongoDbVulnScanner.class);

    private static String[] TIMING_ATTACKS = new String[] {
            "1';var time = new Date().getTime(); while (new Date().getTime() < time + 2000);'",
            "{%S}', $where: 'function(){sleep(2000); return this.name == \"{%S}\"}'})"};

    private static final String[] JSON_INJECTION = {"$ne", "0"};
    private static final String FORM_AUTH_INJECTION = "[$ne]";

    private static ExtensionAuthentication extAuth =
            (ExtensionAuthentication)
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionAuthentication.NAME);

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return "Mongo DB Vuln Scanner";
    }

    @Override
    public String getDescription() {
        return "The application generates a query intended to access or manipulate data in MongoDB, but it does not neutralize or incorrectly neutralizes special elements that can modify the intended logic of the query.";
    }

    private enum FlawType {
        AUTH,
        DATA,
        JS
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        try {
            detectFormAuthenticationBypass(param);
            detectJsonInjection(param);
            detectDataInjection(msg.getResponseBody().toString(), param, value);
            detectJavascriptInjection(param, value);
        } catch (HttpMalformedHeaderException e) {
            e.printStackTrace();
        }
    }

    /**
     * Mongo DB supports inclusion of javascript when executing queries. We try to add js code to
     * sleep the web server and check if response exceeds a certain threshold to verify whether the
     * sleep attack works
     *
     * @param param
     */
    private void detectJavascriptInjection(String param, String value) {
        try {
            HttpMessage newMsg = getNewMsg();
            for (String attack : TIMING_ATTACKS) {
                attack=attack.replace("{%S}",value);
                setParameter(newMsg, param, attack);
                long start = System.currentTimeMillis();
                sendAndReceive(newMsg, false);
                long finish = System.currentTimeMillis();
                long timeElapsed = finish - start;
                if (timeElapsed > 2000) {
                    this.bingo(
                            Alert.RISK_HIGH,
                            Alert.CONFIDENCE_MEDIUM,
                            "Timing Attack",
                            getDescription(),
                            null,
                            param,
                            attack,
                            getOtherInfo(FlawType.JS),
                            getSolution(),
                            newMsg);
                }
            }
        } catch (IOException ex) {
            log.error("caught exception sending request ", ex);
            ;
        }
    }

    /**
     * This attack injects the '[$gt]' operator to a parameter and checks if the returned response
     * is of json while the original response is not . If the second response is JSON we can
     * conclude that the web server returned some unintended data back to the user
     *
     * @param originalResponse
     * @param param
     */
    private void detectDataInjection(String originalResponse, String param, String value) throws HttpMalformedHeaderException {
        HttpMessage newMsg = getNewMsg();
        boolean isJsonRequestBody = Heuristics.isJSONValid(getBaseMsg().getRequestBody().toString());
        if (isJsonRequestBody) {
            newMsg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.FORM_URLENCODED_CONTENT_TYPE);
            String requestBody = getFormDataFromJSONWithInjection(getBaseMsg().getRequestBody().toString(), param, "[$gt]", "");
            newMsg.setRequestBody(requestBody);
        } else {
            setEscapedParameter(newMsg, param + "[$gt]", "");
        }
        try {
            sendAndReceive(newMsg, false);
            boolean isStatusCodeEqual = false;
            if (newMsg.getResponseHeader().getStatusCode()
                    == getBaseMsg().getResponseHeader().getStatusCode()) {
                isStatusCodeEqual = true;
            }
            if (isStatusCodeEqual) {
                if (!newMsg.getResponseBody().toString().equals(originalResponse)) {
                    HttpMessage counterProofMsg = getNewMsg();
                    if (isJsonRequestBody) {
                        counterProofMsg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.FORM_URLENCODED_CONTENT_TYPE);
                        String requestBody = getFormDataFromJSONWithInjection(getBaseMsg().getRequestBody().toString(), param, "[$eq]", value);
                        counterProofMsg.setRequestBody(requestBody);
                    } else {
                        setEscapedParameter(counterProofMsg, param + "[$eq]", "");
                    }
                    sendAndReceive(counterProofMsg, false);
                    if (counterProofMsg.getResponseBody().toString().equals(originalResponse) ||
                            isEmptyResponse(counterProofMsg.getResponseBody().toString(), originalResponse)) {
                        this.bingo(
                                Alert.RISK_HIGH,
                                Alert.CONFIDENCE_MEDIUM,
                                "Query Selector Injection (Data)",
                                getDescription(),
                                null,
                                param,
                                param + "[$gt]",
                                getOtherInfo(FlawType.DATA),
                                getSolution(),
                                newMsg);
                    }
                }
            }

        } catch (IOException ex) {
            log.error("caught exception sending request ", ex);
            ;
        }
    }

    private boolean isEmptyResponse(String counterProofMessage, String originalResponse) {
        return (counterProofMessage.equals("[]") && originalResponse.isEmpty());
    }

    /**
     * We try to attack login pages by appending '[$ne]' operator to username and password fields
     * and then check whether the attack was succesful by detecting if the attack led to the user
     * being redirected to authenticated page
     *
     * @param param
     */
    @SuppressWarnings("deprecation")
    private void detectFormAuthenticationBypass(String param) {
        try {
            // if this url has a form auth continue with this attack
            if (hasFormBasedAuthContext(extAuth.getModel().getSession().getContexts())) {
                boolean loginUrl = false;
                URI requestUri = getBaseMsg().getRequestHeader().getURI();
                List<Context> contextList =
                        extAuth.getModel().getSession().getContextsForUrl(requestUri.getURI());

                for (Context context : contextList) {
                    URI loginUri = extAuth.getLoginRequestURIForContext(context);
                    if (loginUri != null) {
                        if (requestUri.getScheme().equals(loginUri.getScheme())
                                && requestUri.getHost().equals(loginUri.getHost())
                                && requestUri.getPort() == loginUri.getPort()
                                && requestUri.getPath().equals(loginUri.getPath())) {

                            loginUrl = true;
                            break;
                        }
                    }
                }

                // if the message belongs to login url then attack its params
                if (loginUrl) {
                    HttpMessage newMsg = getNewMsg();
                    setEscapedParameter(newMsg, param + FORM_AUTH_INJECTION, "");
                    sendAndReceive(newMsg, false);
                    if (newMsg.getResponseHeader().getStatusCode() >= 200
                            && newMsg.getResponseHeader().getStatusCode() < 400) {
                        if (newMsg.getResponseHeader().getStatusCode() >= 300) {
                            String location = "/";
                            // get location header
                            List<HttpHeaderField> header =
                                    newMsg.getResponseHeader().getHeaders().stream()
                                            .filter(
                                                    h ->
                                                            h.getName()
                                                                    .equals(
                                                                            HttpRequestHeader
                                                                                    .LOCATION))
                                            .collect(Collectors.toList());
                            location = header.get(0).getValue();
                            newMsg.setCookies(newMsg.getResponseHeader().getHttpCookies());
                            newMsg.getRequestHeader().setMethod(HttpRequestHeader.GET);
                            newMsg.getRequestHeader()
                                    .setURI(new URI(this.getParent().getHostAndPort() + location));
                            this.sendAndReceive(newMsg, false);
                        }
                        if (Heuristics.isUserLoggedIn(newMsg.getResponseBody().toString())) {
                            this.bingo(
                                    Alert.RISK_HIGH,
                                    Alert.CONFIDENCE_MEDIUM,
                                    "Query Selector Injection (Authentication)",
                                    this.getDescription(),
                                    null,
                                    param,
                                    param + FORM_AUTH_INJECTION,
                                    this.getOtherInfo(FlawType.AUTH),
                                    this.getSolution(),
                                    newMsg);
                        }
                    }
                }
            }
        } catch (Exception ex) {
            log.error("caught exception while detecting authentication bypass ", ex);
        }
    }

    @SuppressWarnings("deprecation")
    private void detectJsonInjection(String param) {
        try {
            HttpMessage newMsg = getNewMsg();
            JSONObject valueInj = getParamJsonString(JSON_INJECTION);
            setEscapedParameter(newMsg, param , valueInj.toString());
            sendAndReceive(newMsg, false);
            if (newMsg.getResponseHeader().getStatusCode() >= 200
                    && newMsg.getResponseHeader().getStatusCode() < 400) {
                if (newMsg.getResponseHeader().getStatusCode() >= 300) {
                    String location = "/";
                    // get location header
                    List<HttpHeaderField> header =
                            newMsg.getResponseHeader().getHeaders().stream()
                                    .filter(
                                            h ->
                                                    h.getName()
                                                            .equals(
                                                                    HttpRequestHeader
                                                                            .LOCATION))
                                    .collect(Collectors.toList());
                    location = header.get(0).getValue();
                    newMsg.setCookies(newMsg.getResponseHeader().getHttpCookies());
                    newMsg.getRequestHeader().setMethod(HttpRequestHeader.GET);
                    newMsg.getRequestHeader()
                            .setURI(new URI(this.getParent().getHostAndPort() + location));
                    this.sendAndReceive(newMsg, false);
                }
                if (Heuristics.isUserLoggedIn(newMsg.getResponseBody().toString())) {
                    this.bingo(
                            Alert.RISK_HIGH,
                            Alert.CONFIDENCE_MEDIUM,
                            "Json Injection Attack",
                            this.getDescription(),
                            null,
                            param,
                            valueInj.toString(),
                            this.getOtherInfo(FlawType.AUTH),
                            this.getSolution(),
                            newMsg);
                }
            }
        } catch (Exception ex) {
            log.error("caught exception while detecting authentication bypass ", ex);
        }
    }

    private boolean hasFormBasedAuthContext(List<Context> contextList) {
        boolean hasAuth = false;
        for (Context context : contextList) {
            if (context.getAuthenticationMethod()
                    instanceof FormBasedAuthenticationMethodType.FormBasedAuthenticationMethod) {
                hasAuth = true;
                break; // No need to loop further
            }
        }
        return hasAuth;
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        return "Please ensure that you follow one or more of the following techniques, 1. Input validation  2. Parametrized queries 3. Use Stored procedures 4. Use Character Escaping  5. Use a Web Application Firewall";
    }

    public String getOtherInfo(FlawType flawType) {
        String info = "";
        if (flawType == FlawType.AUTH) {
            info =
                    "Malicious users can insert the payload '$ne' to username or password fields and get unauthorized access to the system. \n"
                            + "Sanitize inputs before passing it to the database ";
        } else if (flawType == FlawType.DATA) {
            info =
                    "Malicious users can obtain access to unaintended data by inserting the malicious payload '$gt'";
        } else if (flawType == FlawType.JS) {
            info =
                    "Malicious users can trigger javascript in MongoDb and this can lead to unintended behaviour and even server shutdown";
        }
        return info;
    }

    @Override
    public String getReference() {
        return "https://cwe.mitre.org/data/definitions/943.html";
    }

    /**
     * http://cwe.mitre.org/data/definitions/943.html
     *
     * @return the official CWE id
     */
    @Override
    public int getCweId() {
        return 943;
    }

    /**
     * Seems no WASC defined for this
     *
     * @return the official WASC id
     */
    @Override
    public int getWascId() {
        return 19;
    }

    private static JSONObject getParamJsonString(String[] params) throws JSONException {
        JSONObject internal = new JSONObject();
        internal.put(params[0], params[1]);
        return internal;
    }

    private static String getFormDataFromJSONWithInjection(String jsonString, String param, String injection, String value){
        try {
            StringBuilder formData = new StringBuilder();
            JSONObject obj = new JSONObject(jsonString);
            Iterator<String> itr = obj.keys();
            int i = 0;
            while (itr.hasNext()) {
                Object key = itr.next();
                if (i > 0) {
                    formData.append("&");
                }
                formData.append(key.toString());
                if (key.equals(param)) {
                    formData.append(injection);
                }
                formData.append("=");
                if (key.equals(param)) {
                    formData.append(value);
                } else {
                    formData.append(obj.get(key.toString()));
                }
                i++;
            }
            return formData.toString();
        }
        catch(Exception e){
            log.error("Error parsing request body");
        }
        return "";
    }

}
