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
package org.zaproxy.addon.automation;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.HttpAuthenticationMethodType.HttpAuthenticationMethod;
import org.zaproxy.zap.model.Context;

public class AuthenticationData extends AutomationData {
    public static final String METHOD_HTTP = "http";
    public static final String METHOD_MANUAL = "manual";

    public static final String PARAM_HOSTNAME = "hostname";
    public static final String PARAM_REALM = "realm";
    public static final String PARAM_PORT = "port";

    public static final String VERIFICATION_ELEMENT = "verification";

    private static List<String> validMethods = Arrays.asList(METHOD_MANUAL, METHOD_HTTP);

    private String method;
    private String script;
    private String scriptEngine;
    private Map<String, Object> parameters = new LinkedHashMap<>();
    private VerificationData verification;

    public AuthenticationData() {}

    public AuthenticationData(Context context) {
        AuthenticationMethod authMethod = context.getAuthenticationMethod();
        if (authMethod instanceof HttpAuthenticationMethod) {
            HttpAuthenticationMethod httpAuthMethod = (HttpAuthenticationMethod) authMethod;
            setMethod(AuthenticationData.METHOD_HTTP);
            JobUtils.addPrivateField(parameters, PARAM_REALM, httpAuthMethod);
            JobUtils.addPrivateField(parameters, PARAM_HOSTNAME, httpAuthMethod);
            JobUtils.addPrivateField(parameters, PARAM_PORT, httpAuthMethod);
        }
        if (authMethod != null) {
            setVerification(new VerificationData(context));
        }
    }

    public AuthenticationData(Object data, AutomationProgress progress) {
        if (!(data instanceof LinkedHashMap)) {
            progress.error(Constant.messages.getString("automation.error.env.badauth", data));
        } else {
            LinkedHashMap<?, ?> dataMap = (LinkedHashMap<?, ?>) data;
            JobUtils.applyParamsToObject(
                    dataMap, this, "authentication", new String[] {VERIFICATION_ELEMENT}, progress);

            if (!StringUtils.isEmpty(method)
                    && !validMethods.contains(method.toLowerCase(Locale.ROOT))) {
                progress.error(
                        Constant.messages.getString("automation.error.env.auth.type.bad", data));
            }
            for (Entry<String, Object> entry : parameters.entrySet()) {
                switch (entry.getKey()) {
                    case PARAM_REALM:
                        if (!(entry.getValue() instanceof String)) {
                            progress.error(
                                    Constant.messages.getString(
                                            "automation.error.env.auth.realm.bad", data));
                        }
                        break;
                    case PARAM_HOSTNAME:
                        if (!(entry.getValue() instanceof String)) {
                            progress.error(
                                    Constant.messages.getString(
                                            "automation.error.env.auth.hostname.bad", data));
                        }
                        break;
                    case PARAM_PORT:
                        try {
                            Integer.parseInt(entry.getValue().toString());
                        } catch (NumberFormatException e) {
                            progress.error(
                                    Constant.messages.getString(
                                            "automation.error.env.auth.port.bad", data));
                        }
                        break;
                    default:
                        progress.warn(
                                Constant.messages.getString(
                                        "automation.error.env.auth.param.unknown", data));
                }
            }
            if (dataMap.containsKey(VERIFICATION_ELEMENT)) {
                this.setVerification(
                        new VerificationData(dataMap.get(VERIFICATION_ELEMENT), progress));
            }
        }
    }

    public void initContextAuthentication(Context context, AutomationProgress progress) {
        if (getMethod() != null) {
            switch (getMethod().toLowerCase(Locale.ROOT)) {
                case AuthenticationData.METHOD_MANUAL:
                    // Nothing to do
                    break;
                case AuthenticationData.METHOD_HTTP:
                    HttpAuthenticationMethod httpAuthMethod = new HttpAuthenticationMethod();
                    httpAuthMethod.setHostname(
                            getParameters().get(AuthenticationData.PARAM_HOSTNAME).toString());
                    httpAuthMethod.setRealm(
                            getParameters().get(AuthenticationData.PARAM_REALM).toString());
                    try {
                        httpAuthMethod.setPort(
                                Integer.parseInt(
                                        getParameters()
                                                .get(AuthenticationData.PARAM_PORT)
                                                .toString()));
                    } catch (NumberFormatException e) {
                        // Ignore - will have been already reported
                    }
                    context.setAuthenticationMethod(httpAuthMethod);
                    break;
                default:
                    progress.error(
                            Constant.messages.getString(
                                    "automation.error.env.auth.type.bad", getMethod()));
                    break;
            }
        }
        if (this.verification != null) {
            this.verification.initAuthenticationVerification(context, progress);
        }
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getScript() {
        return script;
    }

    public void setScript(String script) {
        this.script = script;
    }

    public String getScriptEngine() {
        return scriptEngine;
    }

    public void setScriptEngine(String scriptEngine) {
        this.scriptEngine = scriptEngine;
    }

    public Map<String, Object> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, Object> parameters) {
        this.parameters = parameters;
    }

    public void addParameter(String key, String value) {
        this.parameters.put(key, value);
    }

    public VerificationData getVerification() {
        return verification;
    }

    public void setVerification(VerificationData verification) {
        this.verification = verification;
    }
}
