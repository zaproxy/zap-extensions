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
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEngineWrapper;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.sessions.ExtensionSessionManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.session.CookieBasedSessionManagementMethodType.CookieBasedSessionManagementMethod;
import org.zaproxy.zap.session.HttpAuthSessionManagementMethodType.HttpAuthSessionManagementMethod;
import org.zaproxy.zap.session.ScriptBasedSessionManagementMethodType;
import org.zaproxy.zap.session.ScriptBasedSessionManagementMethodType.ScriptBasedSessionManagementMethod;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.session.SessionManagementMethodType;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class SessionManagementData extends AutomationData {

    public static final String METHOD_COOKIE = "cookie";
    public static final String METHOD_HTTP = "http";
    public static final String METHOD_SCRIPT = "script";

    private static List<String> validMethods =
            Arrays.asList(METHOD_COOKIE, METHOD_HTTP, METHOD_SCRIPT);

    private static final String SCRIPT_SESSION_MANAGEMENT_SCRIPT_FIELD = "script";
    private static final String SCRIPT_SESSION_MANAGEMENT_PARAM_VALUES_FIELD = "paramValues";

    private String method;
    private String script;
    private String scriptEngine;
    private Map<String, String> parameters = new LinkedHashMap<>();

    private static final Logger LOG = LogManager.getLogger(SessionManagementData.class);

    public SessionManagementData() {}

    @SuppressWarnings("unchecked")
    public SessionManagementData(Context context) {
        SessionManagementMethod contextMethod = context.getSessionManagementMethod();
        if (contextMethod != null) {
            if (contextMethod instanceof CookieBasedSessionManagementMethod) {
                setMethod(SessionManagementData.METHOD_COOKIE);
            } else if (contextMethod instanceof HttpAuthSessionManagementMethod) {
                setMethod(SessionManagementData.METHOD_HTTP);
            } else if (contextMethod instanceof ScriptBasedSessionManagementMethod) {
                setMethod(SessionManagementData.METHOD_SCRIPT);
                ScriptWrapper wrapper =
                        (ScriptWrapper)
                                JobUtils.getPrivateField(
                                        contextMethod, SCRIPT_SESSION_MANAGEMENT_SCRIPT_FIELD);
                if (wrapper != null) {
                    setScript(wrapper.getFile().getAbsolutePath());
                    setScriptEngine(wrapper.getEngine().getEngineName());
                    Object paramValues =
                            JobUtils.getPrivateField(
                                    contextMethod, SCRIPT_SESSION_MANAGEMENT_PARAM_VALUES_FIELD);
                    if (paramValues instanceof Map<?, ?>) {
                        setParameters((Map<String, String>) paramValues);
                    }
                }
            }
        }
    }

    public SessionManagementData(Object data, AutomationProgress progress) {
        if (!(data instanceof LinkedHashMap)) {
            progress.error(
                    Constant.messages.getString("automation.error.env.badsessionmgmt", data));
        } else {
            JobUtils.applyParamsToObject(
                    (LinkedHashMap<?, ?>) data, this, "sessionManagement", null, progress);

            if (!StringUtils.isEmpty(method)
                    && !validMethods.contains(method.toLowerCase(Locale.ROOT))) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.env.sessionmgmt.type.bad", data));
            }
        }
    }

    @SuppressWarnings("unchecked")
    public void initContextSessionManagement(Context context, AutomationProgress progress) {
        switch (getMethod().toLowerCase(Locale.ROOT)) {
            case SessionManagementData.METHOD_COOKIE:
                context.setSessionManagementMethod(
                        new CookieBasedSessionManagementMethod(context.getId()));
                break;
            case SessionManagementData.METHOD_HTTP:
                context.setSessionManagementMethod(new HttpAuthSessionManagementMethod());
                break;
            case SessionManagementData.METHOD_SCRIPT:
                File f = new File(getScript());
                if (!f.exists() || !f.canRead()) {
                    progress.error(
                            Constant.messages.getString(
                                    "automation.error.env.sessionmgmt.script.bad",
                                    f.getAbsolutePath()));
                } else {
                    ScriptWrapper sw = getScriptWrapper(f, getScriptEngine(), progress);
                    ScriptBasedSessionManagementMethod smm =
                            getScriptBasedSessionManagementMethod(context.getId());
                    if (sw != null && smm != null) {
                        Object paramValues =
                                JobUtils.getPrivateField(
                                        smm, SCRIPT_SESSION_MANAGEMENT_PARAM_VALUES_FIELD);
                        if (paramValues instanceof Map<?, ?>) {
                            ((Map<String, String>) paramValues).putAll(getParameters());
                        }
                        JobUtils.setPrivateField(
                                smm, SCRIPT_SESSION_MANAGEMENT_PARAM_VALUES_FIELD, paramValues);
                        context.setSessionManagementMethod(smm);

                        try {
                            // OK, this does look weird, but it is the easiest way to actually get
                            // the script data loaded :/
                            SessionManagementMethodType type = smm.getType();
                            Configuration config = new ZapXmlConfiguration();
                            type.exportData(config, smm);
                            type.importData(config, smm);
                        } catch (ConfigurationException e) {
                            LOG.error("Error setting script session management", e);
                            progress.error(
                                    Constant.messages.getString(
                                            "automation.error.unexpected.internal",
                                            e.getMessage()));
                        }
                    }
                }
                break;
            default:
                progress.error(
                        Constant.messages.getString(
                                "automation.error.env.sessionmgmt.type.bad", getMethod()));
                break;
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

    public Map<String, String> getParameters() {
        return parameters;
    }

    public void setParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }

    private ScriptWrapper getScriptWrapper(
            File file, String engineName, AutomationProgress progress) {
        ExtensionScript extScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        ScriptWrapper wrapper = null;
        if (extScript != null) {
            // Use existing script if its already loaded
            for (ScriptWrapper sw :
                    extScript.getScripts(
                            ScriptBasedSessionManagementMethodType.SCRIPT_TYPE_SESSION)) {
                try {
                    if (Files.isSameFile(sw.getFile().toPath(), file.toPath())
                            && sw.getEngineName().equals(engineName)) {
                        wrapper = sw;
                        break;
                    }
                } catch (IOException e) {
                    // Ignore
                }
            }
            if (wrapper == null) {
                // Register the script
                ScriptEngineWrapper engineWrapper = extScript.getEngineWrapper(engineName);
                if (engineWrapper == null) {
                    progress.error(
                            Constant.messages.getString(
                                    "automation.error.env.sessionmgmt.engine.bad", engineName));
                } else {
                    ScriptType type =
                            extScript.getScriptType(
                                    ScriptBasedSessionManagementMethodType.SCRIPT_TYPE_SESSION);
                    LOG.debug("Loading script {}", file.getAbsolutePath());
                    try {
                        wrapper =
                                extScript.loadScript(
                                        new ScriptWrapper(
                                                file.getName(),
                                                "",
                                                engineWrapper,
                                                type,
                                                true,
                                                file));
                        extScript.addScript(wrapper, false);
                    } catch (IOException e) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.env.sessionmgmt.script.bad",
                                        file.getAbsolutePath()));
                    }
                }
            }
        }
        return wrapper;
    }

    private ScriptBasedSessionManagementMethod getScriptBasedSessionManagementMethod(
            int contextId) {
        ExtensionSessionManagement extSessMgmt =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionSessionManagement.class);
        if (extSessMgmt != null) {
            SessionManagementMethodType type =
                    extSessMgmt.getSessionManagementMethodTypeForIdentifier(2);
            SessionManagementMethod smm = type.createSessionManagementMethod(contextId);
            if (smm instanceof ScriptBasedSessionManagementMethod) {
                return (ScriptBasedSessionManagementMethod) smm;
            }
        }
        return null;
    }
}
