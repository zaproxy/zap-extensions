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

import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.FormBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.FormBasedAuthenticationMethodType.FormBasedAuthenticationMethod;
import org.zaproxy.zap.authentication.HttpAuthenticationMethodType.HttpAuthenticationMethod;
import org.zaproxy.zap.authentication.JsonBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.JsonBasedAuthenticationMethodType.JsonBasedAuthenticationMethod;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType.ScriptBasedAuthenticationMethod;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class AuthenticationData extends AutomationData {
    public static final String METHOD_HTTP = "http";
    public static final String METHOD_FORM = "form";
    public static final String METHOD_JSON = "json";
    public static final String METHOD_MANUAL = "manual";
    public static final String METHOD_SCRIPT = "script";

    public static final String PARAM_HOSTNAME = "hostname";
    public static final String PARAM_REALM = "realm";
    public static final String PARAM_PORT = "port";
    public static final String PARAM_LOGIN_PAGE_URL = "loginPageUrl";
    public static final String PARAM_LOGIN_REQUEST_URL = "loginRequestUrl";
    public static final String PARAM_LOGIN_REQUEST_BODY = "loginRequestBody";
    public static final String PARAM_SCRIPT = "script";
    public static final String PARAM_SCRIPT_ENGINE = "scriptEngine";

    /** Field name in the underlying PostBasedAuthenticationMethod class * */
    protected static final String FIELD_LOGIN_REQUEST_URL = "loginRequestURL";

    private static final String BAD_FIELD_ERROR_MSG = "automation.error.env.auth.field.bad";

    public static final String VERIFICATION_ELEMENT = "verification";

    private static List<String> validMethods =
            Arrays.asList(METHOD_MANUAL, METHOD_HTTP, METHOD_FORM, METHOD_JSON, METHOD_SCRIPT);

    private String method;
    private Map<String, Object> parameters = new LinkedHashMap<>();
    private VerificationData verification;

    private static final Logger LOG = LogManager.getLogger(AuthenticationData.class);

    public AuthenticationData() {}

    public AuthenticationData(Context context) {
        AuthenticationMethod authMethod = context.getAuthenticationMethod();
        if (authMethod instanceof HttpAuthenticationMethod) {
            HttpAuthenticationMethod httpAuthMethod = (HttpAuthenticationMethod) authMethod;
            setMethod(AuthenticationData.METHOD_HTTP);
            JobUtils.addPrivateField(parameters, PARAM_REALM, httpAuthMethod);
            JobUtils.addPrivateField(parameters, PARAM_HOSTNAME, httpAuthMethod);
            JobUtils.addPrivateField(parameters, PARAM_PORT, httpAuthMethod);
        } else if (authMethod instanceof FormBasedAuthenticationMethod) {
            FormBasedAuthenticationMethod formAuthMethod =
                    (FormBasedAuthenticationMethod) authMethod;
            setMethod(AuthenticationData.METHOD_FORM);
            JobUtils.addPrivateField(parameters, PARAM_LOGIN_PAGE_URL, formAuthMethod);
            JobUtils.addPrivateField(
                    parameters, PARAM_LOGIN_REQUEST_URL, FIELD_LOGIN_REQUEST_URL, formAuthMethod);
            JobUtils.addPrivateField(parameters, PARAM_LOGIN_REQUEST_BODY, formAuthMethod);
        } else if (authMethod instanceof JsonBasedAuthenticationMethod) {
            JsonBasedAuthenticationMethod jsonAuthMethod =
                    (JsonBasedAuthenticationMethod) authMethod;
            setMethod(AuthenticationData.METHOD_JSON);
            JobUtils.addPrivateField(parameters, PARAM_LOGIN_PAGE_URL, jsonAuthMethod);
            JobUtils.addPrivateField(
                    parameters, PARAM_LOGIN_REQUEST_URL, FIELD_LOGIN_REQUEST_URL, jsonAuthMethod);
            JobUtils.addPrivateField(parameters, PARAM_LOGIN_REQUEST_BODY, jsonAuthMethod);
        } else if (authMethod instanceof ScriptBasedAuthenticationMethod) {
            ScriptBasedAuthenticationMethod scriptAuthMethod =
                    (ScriptBasedAuthenticationMethod) authMethod;
            ScriptWrapper sw = (ScriptWrapper) JobUtils.getPrivateField(scriptAuthMethod, "script");
            if (sw != null) {
                setMethod(AuthenticationData.METHOD_SCRIPT);
                parameters.put(PARAM_SCRIPT, sw.getFile().getAbsolutePath());
                parameters.put(PARAM_SCRIPT_ENGINE, sw.getEngineName());
                @SuppressWarnings("unchecked")
                Map<String, String> paramValues =
                        (Map<String, String>)
                                JobUtils.getPrivateField(scriptAuthMethod, "paramValues");
                for (Entry<String, String> entry : paramValues.entrySet()) {
                    parameters.put(entry.getKey(), entry.getValue());
                }
            }
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
                    case PARAM_PORT:
                        try {
                            Integer.parseInt(entry.getValue().toString());
                        } catch (NumberFormatException e) {
                            progress.error(
                                    Constant.messages.getString(
                                            BAD_FIELD_ERROR_MSG, PARAM_PORT, data));
                        }
                        break;
                    default:
                        if (!(entry.getValue() instanceof String)) {
                            progress.error(
                                    Constant.messages.getString(
                                            BAD_FIELD_ERROR_MSG, entry.getKey(), data));
                        }
                        break;
                }
            }
            if (dataMap.containsKey(VERIFICATION_ELEMENT)) {
                this.setVerification(
                        new VerificationData(dataMap.get(VERIFICATION_ELEMENT), progress));
            }
        }
    }

    public void initContextAuthentication(
            Context context, AutomationProgress progress, AutomationEnvironment env) {
        if (getMethod() != null) {
            switch (getMethod().toLowerCase(Locale.ROOT)) {
                case AuthenticationData.METHOD_MANUAL:
                    // Nothing to do
                    break;
                case AuthenticationData.METHOD_HTTP:
                    HttpAuthenticationMethod httpAuthMethod = new HttpAuthenticationMethod();
                    httpAuthMethod.setHostname(
                            env.replaceVars(
                                    getParameters().get(AuthenticationData.PARAM_HOSTNAME)));
                    httpAuthMethod.setRealm(
                            env.replaceVars(getParameters().get(AuthenticationData.PARAM_REALM)));
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
                case AuthenticationData.METHOD_FORM:
                    FormBasedAuthenticationMethodType formType =
                            new FormBasedAuthenticationMethodType();
                    FormBasedAuthenticationMethod formAuthMethod =
                            formType.createAuthenticationMethod(context.getId());
                    JobUtils.setPrivateField(
                            formAuthMethod,
                            AuthenticationData.PARAM_LOGIN_PAGE_URL,
                            env.replaceVars(
                                    getParameters().get(AuthenticationData.PARAM_LOGIN_PAGE_URL)));
                    // Note field name is different to param name
                    JobUtils.setPrivateField(
                            formAuthMethod,
                            FIELD_LOGIN_REQUEST_URL,
                            env.replaceVars(
                                    getParameters()
                                            .get(AuthenticationData.PARAM_LOGIN_REQUEST_URL)));
                    JobUtils.setPrivateField(
                            formAuthMethod,
                            AuthenticationData.PARAM_LOGIN_REQUEST_BODY,
                            env.replaceVars(
                                    getParameters()
                                            .get(AuthenticationData.PARAM_LOGIN_REQUEST_BODY)));
                    context.setAuthenticationMethod(formAuthMethod);
                    break;
                case AuthenticationData.METHOD_JSON:
                    JsonBasedAuthenticationMethodType jsonType =
                            new JsonBasedAuthenticationMethodType();
                    JsonBasedAuthenticationMethod jsonAuthMethod =
                            jsonType.createAuthenticationMethod(context.getId());
                    JobUtils.setPrivateField(
                            jsonAuthMethod,
                            AuthenticationData.PARAM_LOGIN_PAGE_URL,
                            env.replaceVars(
                                    getParameters().get(AuthenticationData.PARAM_LOGIN_PAGE_URL)));
                    // Note field name is different to param name
                    JobUtils.setPrivateField(
                            jsonAuthMethod,
                            FIELD_LOGIN_REQUEST_URL,
                            env.replaceVars(
                                    getParameters()
                                            .get(AuthenticationData.PARAM_LOGIN_REQUEST_URL)));

                    JobUtils.setPrivateField(
                            jsonAuthMethod,
                            AuthenticationData.PARAM_LOGIN_REQUEST_BODY,
                            env.replaceVars(
                                    getParameters()
                                            .get(AuthenticationData.PARAM_LOGIN_REQUEST_BODY)));
                    context.setAuthenticationMethod(jsonAuthMethod);
                    break;
                case AuthenticationData.METHOD_SCRIPT:
                    File f = new File(parameters.getOrDefault(PARAM_SCRIPT, "").toString());
                    if (!f.exists() || !f.canRead()) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.env.sessionmgmt.script.bad",
                                        f.getAbsolutePath()));
                    } else {
                        ScriptWrapper sw =
                                JobUtils.getScriptWrapper(
                                        f,
                                        ScriptBasedAuthenticationMethodType.SCRIPT_TYPE_AUTH,
                                        parameters.getOrDefault(PARAM_SCRIPT_ENGINE, "").toString(),
                                        progress);
                        ScriptBasedAuthenticationMethodType scriptType =
                                new ScriptBasedAuthenticationMethodType();
                        ScriptBasedAuthenticationMethod scriptMethod =
                                scriptType.createAuthenticationMethod(context.getId());

                        if (sw == null) {
                            LOG.error(
                                    "Error setting script authentication - failed to find script wrapper");
                            progress.error(
                                    Constant.messages.getString(
                                            "automation.error.env.auth.script.bad",
                                            f.getAbsolutePath()));
                        } else {
                            scriptMethod.loadScript(sw);
                            JobUtils.setPrivateField(
                                    scriptMethod, "paramValues", getScriptParameters(env));

                            try {
                                // OK, this does look weird, but it is the easiest way to actually
                                // get the script data loaded :/
                                Configuration config = new ZapXmlConfiguration();
                                scriptType.exportData(config, scriptMethod);
                                scriptType.importData(config, scriptMethod);
                            } catch (ConfigurationException e) {
                                LOG.error("Error setting script authentication", e);
                                progress.error(
                                        Constant.messages.getString(
                                                "automation.error.unexpected.internal",
                                                e.getMessage()));
                            }

                            context.setAuthenticationMethod(scriptMethod);
                        }
                    }
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

    private Map<String, String> getScriptParameters(AutomationEnvironment env) {
        Map<String, String> map = new HashMap<>();
        for (Entry<String, Object> entry : this.parameters.entrySet()) {
            // In theory we could filter out all of the parameters we know about, but they shouldnt
            // cause any problems
            if (entry.getValue() instanceof String) {
                // Script variables must be strings, can ignore anything else
                map.put(entry.getKey(), env.replaceVars(entry.getValue()));
            }
        }
        return map;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
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
