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

import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.File;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.reflect.MethodUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.ContextWrapper.UserData;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethodType;
import org.zaproxy.zap.authentication.FormBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.FormBasedAuthenticationMethodType.FormBasedAuthenticationMethod;
import org.zaproxy.zap.authentication.HttpAuthenticationMethodType.HttpAuthenticationMethod;
import org.zaproxy.zap.authentication.JsonBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.JsonBasedAuthenticationMethodType.JsonBasedAuthenticationMethod;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType.ScriptBasedAuthenticationMethod;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class AuthenticationData extends AutomationData {

    public static final String METHOD_HTTP = "http";
    public static final String METHOD_FORM = "form";
    public static final String METHOD_JSON = "json";
    public static final String METHOD_MANUAL = "manual";
    public static final String METHOD_SCRIPT = "script";
    public static final String METHOD_BROWSER = "browser";
    public static final String METHOD_AUTO = "autodetect";
    public static final String METHOD_CLIENT = "client";

    public static final String PARAM_HOSTNAME = "hostname";
    public static final String PARAM_REALM = "realm";
    public static final String PARAM_PORT = "port";
    public static final String PARAM_BROWSER_ID = "browserId";
    public static final String PARAM_DIAGNOSTICS = "diagnostics";
    public static final String PARAM_LOGIN_PAGE_URL = "loginPageUrl";
    public static final String PARAM_LOGIN_PAGE_WAIT = "loginPageWait";
    public static final String PARAM_LOGIN_REQUEST_URL = "loginRequestUrl";
    public static final String PARAM_LOGIN_REQUEST_BODY = "loginRequestBody";
    public static final String PARAM_SCRIPT = "script";
    public static final String PARAM_SCRIPT_ENGINE = "scriptEngine";

    // TODO: Plan to change once the core supports dynamic methods better
    protected static final String CLIENT_SCRIPT_BASED_AUTH_METHOD_CLASSNAME =
            "org.zaproxy.addon.authhelper.client.ClientScriptBasedAuthenticationMethodType.ClientScriptBasedAuthenticationMethod";
    protected static final String BROWSER_BASED_AUTH_METHOD_CLASSNAME =
            "org.zaproxy.addon.authhelper.BrowserBasedAuthenticationMethodType.BrowserBasedAuthenticationMethod";

    /** Field name in the underlying PostBasedAuthenticationMethod class * */
    protected static final String FIELD_LOGIN_REQUEST_URL = "loginRequestURL";

    private static final String BAD_FIELD_ERROR_MSG = "automation.error.env.auth.field.bad";
    private static final String PRIVATE_FIELD_SCRIPT = "script";

    public static final String VERIFICATION_ELEMENT = "verification";

    private static List<String> validMethods =
            Arrays.asList(
                    METHOD_MANUAL,
                    METHOD_HTTP,
                    METHOD_FORM,
                    METHOD_JSON,
                    METHOD_SCRIPT,
                    METHOD_BROWSER,
                    METHOD_AUTO,
                    METHOD_CLIENT);

    private String method;
    private Map<String, Object> parameters = new LinkedHashMap<>();
    private VerificationData verification;

    private static final Logger LOGGER = LogManager.getLogger(AuthenticationData.class);

    public AuthenticationData() {}

    public AuthenticationData(Context context) {
        this(context, List.of());
    }

    public AuthenticationData(Context context, List<UserData> users) {
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
        } else if (authMethod != null
                && authMethod
                        .getClass()
                        .getCanonicalName()
                        .equals(CLIENT_SCRIPT_BASED_AUTH_METHOD_CLASSNAME)) {
            ScriptWrapper sw =
                    (ScriptWrapper) JobUtils.getPrivateField(authMethod, PRIVATE_FIELD_SCRIPT);
            LOGGER.debug("Matched client script class");
            if (sw != null) {
                setMethod(METHOD_CLIENT);
                parameters.put(PARAM_SCRIPT, sw.getFile().getAbsolutePath());
                parameters.put(PARAM_SCRIPT_ENGINE, sw.getEngineName());
                @SuppressWarnings("unchecked")
                Map<String, String> paramValues =
                        (Map<String, String>) JobUtils.getPrivateField(authMethod, "paramValues");
                for (Entry<String, String> entry : paramValues.entrySet()) {
                    parameters.put(entry.getKey(), entry.getValue());
                }
            }
        } else if (authMethod instanceof ScriptBasedAuthenticationMethod scriptAuthMethod) {
            ScriptWrapper sw =
                    (ScriptWrapper)
                            JobUtils.getPrivateField(scriptAuthMethod, PRIVATE_FIELD_SCRIPT);
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
        } else if (authMethod != null
                && authMethod
                        .getClass()
                        .getCanonicalName()
                        .equals(BROWSER_BASED_AUTH_METHOD_CLASSNAME)) {
            // Plan to change once the core supports dynamic methods better
            setMethod(METHOD_BROWSER);
            JobUtils.addPrivateField(parameters, PARAM_LOGIN_PAGE_URL, authMethod);
            JobUtils.addPrivateField(parameters, PARAM_LOGIN_PAGE_WAIT, authMethod);
            JobUtils.addPrivateField(parameters, PARAM_BROWSER_ID, authMethod);

            try {
                Method method = authMethod.getClass().getMethod("toMap", Map.class);
                method.invoke(authMethod, parameters);
            } catch (Exception e) {
                LOGGER.error("An error occurred while saving steps:", e);
            }

            totpMethodToUser(parameters, users);

        } else if (authMethod != null
                && authMethod
                        .getClass()
                        .getCanonicalName()
                        .equals(
                                "org.zaproxy.addon.authhelper.AutoDetectAuthenticationMethodType.AutoDetectAuthenticationMethod")) {
            // Plan to change once the core supports dynamic methods better
            setMethod(METHOD_AUTO);
        }
        if (authMethod != null) {
            setVerification(new VerificationData(context));
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static void totpMethodToUser(
            Map<String, Object> parameters, List<ContextWrapper.UserData> users) {
        if (users == null || users.isEmpty()) {
            return;
        }

        var user = users.get(0);
        Object data = parameters.get("steps");
        if (!(data instanceof List steps)) {
            return;
        }

        for (Iterator<?> it = steps.iterator(); it.hasNext(); ) {
            Map<String, Object> object = (Map<String, Object>) it.next();
            if (isTotpType(object)) {
                user.getInternalCredentials()
                        .setTotp(
                                JsonMapper.builder()
                                        .build()
                                        .convertValue(
                                                object.remove("totp"), UserData.TotpData.class));
                return;
            }
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static Map<String, Object> totpUserToMethod(
            Map<String, Object> parameters,
            List<ContextWrapper.UserData> users,
            AutomationEnvironment env) {
        if (users == null) {
            return parameters;
        }

        var totpData =
                users.stream()
                        .map(ContextWrapper.UserData::getInternalCredentials)
                        .map(ContextWrapper.UserData.Credentials::getTotp)
                        .filter(Objects::nonNull)
                        .findFirst()
                        .orElse(null);
        if (totpData == null) {
            return parameters;
        }

        Object data = parameters.get("steps");
        if (!(data instanceof List steps)) {
            return parameters;
        }

        for (Iterator<?> it = steps.iterator(); it.hasNext(); ) {
            Map<String, Object> object = (Map<String, Object>) it.next();
            if (isTotpType(object)) {
                Map<String, Object> totpMap =
                        JsonMapper.builder().build().convertValue(totpData, LinkedHashMap.class);
                totpMap.replaceAll((k, v) -> env.replaceVars(v));
                object.put("totp", totpMap);
            }
        }
        return parameters;
    }

    private static boolean isTotpType(Map<String, Object> object) {
        return "TOTP_FIELD".equals(object.get("type"));
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
                    case PARAM_LOGIN_PAGE_WAIT:
                        try {
                            Integer.parseInt(entry.getValue().toString());
                        } catch (NumberFormatException e) {
                            progress.error(
                                    Constant.messages.getString(
                                            BAD_FIELD_ERROR_MSG, PARAM_PORT, data));
                        }
                        break;
                    case PARAM_DIAGNOSTICS:
                    case "steps":
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
        initContextAuthentication(context, progress, env, List.of());
    }

    public void initContextAuthentication(
            Context context,
            AutomationProgress progress,
            AutomationEnvironment env,
            List<ContextWrapper.UserData> users) {
        if (getMethod() != null) {
            ExtensionAuthentication extAuth = null;
            if (Control.getSingleton() != null) {
                // Will only be null in the unit tests
                extAuth =
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionAuthentication.class);
            }

            switch (getMethod().toLowerCase(Locale.ROOT)) {
                case AuthenticationData.METHOD_MANUAL:
                    // Nothing to do
                    break;
                case AuthenticationData.METHOD_HTTP:
                    HttpAuthenticationMethod httpAuthMethod = new HttpAuthenticationMethod();
                    httpAuthMethod.setHostname(
                            env.replaceVars(
                                    getParameters().get(AuthenticationData.PARAM_HOSTNAME)));
                    var realm =
                            env.replaceVars(getParameters().get(AuthenticationData.PARAM_REALM));
                    if (realm == null) {
                        realm = "";
                    }
                    httpAuthMethod.setRealm(realm);
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
                case AuthenticationData.METHOD_CLIENT:
                    File clientScript =
                            JobUtils.getFile(
                                    parameters.getOrDefault(PARAM_SCRIPT, "").toString(),
                                    env.getPlan());
                    if (!clientScript.exists() || !clientScript.canRead()) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.env.sessionmgmt.script.bad",
                                        clientScript.getAbsolutePath()));
                    } else {
                        ScriptWrapper sw =
                                JobUtils.getScriptWrapper(
                                        clientScript,
                                        ScriptBasedAuthenticationMethodType.SCRIPT_TYPE_AUTH,
                                        parameters.getOrDefault(PARAM_SCRIPT_ENGINE, "").toString(),
                                        progress);

                        AuthenticationMethodType clientScriptType =
                                extAuth.getAuthenticationMethodTypeForIdentifier(8);
                        LOGGER.info("Loaded client script auth method type {}.", clientScriptType);
                        AuthenticationMethod clientScriptMethod =
                                clientScriptType.createAuthenticationMethod(context.getId());

                        if (sw == null) {
                            LOGGER.error(
                                    "Error setting script authentication - failed to find script wrapper");
                            progress.error(
                                    Constant.messages.getString(
                                            "automation.error.env.auth.script.bad",
                                            clientScript.getAbsolutePath()));
                        } else {
                            JobUtils.setPrivateField(
                                    clientScriptMethod,
                                    "diagnostics",
                                    parameters.getOrDefault(PARAM_DIAGNOSTICS, false));

                            try {
                                MethodUtils.invokeMethod(clientScriptMethod, "loadScript", sw);
                            } catch (Exception e) {
                                LOGGER.error(e.getMessage(), e);
                            }
                            JobUtils.setPrivateField(
                                    clientScriptMethod, "paramValues", getScriptParameters(env));

                            reloadAuthenticationMethod(clientScriptMethod, progress);
                            context.setAuthenticationMethod(clientScriptMethod);
                        }
                    }
                    break;
                case AuthenticationData.METHOD_SCRIPT:
                    File f =
                            JobUtils.getFile(
                                    parameters.getOrDefault(PARAM_SCRIPT, "").toString(),
                                    env.getPlan());
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

                        AuthenticationMethodType scriptType =
                                new ScriptBasedAuthenticationMethodType();
                        LOGGER.debug("Loaded script auth method type");

                        AuthenticationMethod scriptMethod =
                                scriptType.createAuthenticationMethod(context.getId());

                        if (sw == null) {
                            LOGGER.error(
                                    "Error setting script authentication - failed to find script wrapper");
                            progress.error(
                                    Constant.messages.getString(
                                            "automation.error.env.auth.script.bad",
                                            f.getAbsolutePath()));
                        } else {
                            try {
                                MethodUtils.invokeMethod(scriptMethod, "loadScript", sw);
                            } catch (Exception e) {
                                LOGGER.error(e.getMessage(), e);
                            }
                            JobUtils.setPrivateField(
                                    scriptMethod, "paramValues", getScriptParameters(env));

                            reloadAuthenticationMethod(scriptMethod, progress);
                            context.setAuthenticationMethod(scriptMethod);
                        }
                    }
                    break;
                case AuthenticationData.METHOD_BROWSER:
                    // This should be handled dynamically, but that required core changes
                    AuthenticationMethodType authBrowserType =
                            extAuth.getAuthenticationMethodTypeForIdentifier(6);

                    if (authBrowserType != null) {
                        AuthenticationMethod am =
                                authBrowserType.createAuthenticationMethod(context.getId());

                        JobUtils.setPrivateField(
                                am,
                                "diagnostics",
                                parameters.getOrDefault(PARAM_DIAGNOSTICS, false));

                        JobUtils.setPrivateField(
                                am,
                                AuthenticationData.PARAM_LOGIN_PAGE_URL,
                                env.replaceVars(
                                        getParameters()
                                                .get(AuthenticationData.PARAM_LOGIN_PAGE_URL)));

                        Object browserIdObj =
                                getParameters().get(AuthenticationData.PARAM_BROWSER_ID);
                        if (browserIdObj != null && browserIdObj instanceof String) {
                            JobUtils.setPrivateField(
                                    am, AuthenticationData.PARAM_BROWSER_ID, (String) browserIdObj);
                        }
                        Object loginPageWaitObj =
                                getParameters().get(AuthenticationData.PARAM_LOGIN_PAGE_WAIT);
                        if (loginPageWaitObj instanceof Integer) {
                            int loginPageWait = JobUtils.unBox((Integer) loginPageWaitObj);
                            if (loginPageWait > 0) {
                                JobUtils.setPrivateField(
                                        am,
                                        AuthenticationData.PARAM_LOGIN_PAGE_WAIT,
                                        loginPageWait);
                            }
                        }

                        try {
                            Method method = am.getClass().getMethod("fromMap", Map.class);
                            method.invoke(am, totpUserToMethod(getParameters(), users, env));
                        } catch (Exception e) {
                            LOGGER.error("An error occurred while reading steps:", e);
                        }

                        reloadAuthenticationMethod(am, progress);
                        context.setAuthenticationMethod(am);

                    } else {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.env.auth.type.bad", getMethod()));
                    }
                    break;

                case AuthenticationData.METHOD_AUTO:
                    // This should be handled dynamically, but that required core changes
                    AuthenticationMethodType authAutoType =
                            extAuth.getAuthenticationMethodTypeForIdentifier(7);

                    if (authAutoType != null) {
                        AuthenticationMethod am =
                                authAutoType.createAuthenticationMethod(context.getId());

                        reloadAuthenticationMethod(am, progress);
                        context.setAuthenticationMethod(am);

                    } else {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.env.auth.type.bad", getMethod()));
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

    private void reloadAuthenticationMethod(AuthenticationMethod am, AutomationProgress progress) {
        try {
            // OK, this does look weird, but it is the easiest way to actually get
            // the session management data loaded :/
            AuthenticationMethodType type = am.getType();
            Configuration config = new ZapXmlConfiguration();
            type.exportData(config, am);
            type.importData(config, am);
        } catch (ConfigurationException e) {
            LOGGER.error("Error setting authentication", e);
            progress.error(
                    Constant.messages.getString(
                            "automation.error.unexpected.internal", e.getMessage()));
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
