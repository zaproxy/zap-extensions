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
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Session;
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

public class ContextWrapper {

    private Context context;

    private Data data;

    private static final String SCRIPT_SESSION_MANAGEMENT_SCRIPT_FIELD = "script";
    private static final String SCRIPT_SESSION_MANAGEMENT_PARAM_VALUES_FIELD = "paramValues";

    private static final Logger LOG = LogManager.getLogger(ContextWrapper.class);

    public ContextWrapper(Data data) {
        this.data = data;
    }

    /**
     * Create a ContextWrapper from an existing Context
     *
     * @param context the existing context
     */
    public ContextWrapper(Context context) {
        this.context = context;
        this.data = new Data();
        this.data.setName(context.getName());
        this.data.setIncludePaths(context.getIncludeInContextRegexs());
        this.data.setExcludePaths(context.getExcludeFromContextRegexs());
        // Contexts dont actually define the starting URL, but we need at least one
        for (String url : context.getIncludeInContextRegexs()) {
            if (url.endsWith(".*")) {
                this.addUrl(url.substring(0, url.length() - 2));
            }
        }
        SessionManagementMethod method = context.getSessionManagementMethod();
        if (method != null) {
            SessionManagementData smData = new SessionManagementData();
            if (method instanceof CookieBasedSessionManagementMethod) {
                smData.setMethod(SessionManagementData.METHOD_COOKIE);
                this.data.setSessionManagement(smData);
            } else if (method instanceof HttpAuthSessionManagementMethod) {
                smData.setMethod(SessionManagementData.METHOD_HTTP);
                this.data.setSessionManagement(smData);
            } else if (method instanceof ScriptBasedSessionManagementMethod) {
                smData.setMethod(SessionManagementData.METHOD_SCRIPT);
                ScriptWrapper wrapper = getScriptWrapper(method);
                if (wrapper != null) {
                    Map<String, String> paramValues =
                            getParamValues((ScriptBasedSessionManagementMethod) method);
                    smData.setScript(wrapper.getFile().getAbsolutePath());
                    smData.setScriptEngine(wrapper.getEngine().getEngineName());
                    if (paramValues != null) {
                        smData.setParameters(paramValues);
                    }
                    this.data.setSessionManagement(smData);
                }
            }
        }
    }

    private ScriptWrapper getScriptWrapper(SessionManagementMethod method) {
        try {
            // Have to use reflection on private field :(
            Field scriptField =
                    ScriptBasedSessionManagementMethod.class.getDeclaredField(
                            SCRIPT_SESSION_MANAGEMENT_SCRIPT_FIELD);
            return (ScriptWrapper) FieldUtils.readField(scriptField, method, true);
        } catch (Exception e) {
            LOG.error("Failed get ScriptBasedSessionManagementMethod script field", e);
        }
        return null;
    }

    private void setScriptWrapper(ScriptBasedSessionManagementMethod method, ScriptWrapper value) {
        try {
            // Have to use reflection on private field :(
            Field scriptField =
                    ScriptBasedSessionManagementMethod.class.getDeclaredField(
                            SCRIPT_SESSION_MANAGEMENT_SCRIPT_FIELD);
            FieldUtils.writeField(scriptField, method, value, true);
        } catch (Exception e) {
            LOG.error("Failed set ScriptBasedSessionManagementMethod script field", e);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> getParamValues(ScriptBasedSessionManagementMethod method) {
        try {
            // Have to use reflection on private field :(
            Field paramValuesField =
                    ScriptBasedSessionManagementMethod.class.getDeclaredField(
                            SCRIPT_SESSION_MANAGEMENT_PARAM_VALUES_FIELD);
            return (Map<String, String>) FieldUtils.readField(paramValuesField, method, true);
        } catch (Exception e) {
            LOG.error("Failed get ScriptBasedSessionManagementMethod paramValues field", e);
        }
        return null;
    }

    public ContextWrapper(Map<?, ?> contextData, AutomationProgress progress) {
        this.data = new Data();
        for (Entry<?, ?> cdata : contextData.entrySet()) {
            Object value = cdata.getValue();
            if (value == null) {
                continue;
            }
            switch (cdata.getKey().toString()) {
                case "name":
                    data.setName(value.toString());
                    break;
                case "urls":
                    if (!(value instanceof ArrayList)) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.context.badurlslist", value));

                    } else {
                        ArrayList<?> urlList = (ArrayList<?>) value;
                        for (Object urlObj : urlList) {
                            String url = urlObj.toString();
                            data.getUrls().add(url);
                            validateUrl(url, progress);
                        }
                    }
                    break;
                case "url":
                    // For backwards compatibility
                    String url = value.toString();
                    data.getUrls().add(url);
                    validateUrl(url, progress);
                    progress.warn(
                            Constant.messages.getString("automation.error.context.url.deprecated"));
                    break;
                case "includePaths":
                    data.setIncludePaths(verifyRegexes(value, "badincludelist", progress));
                    break;
                case "excludePaths":
                    data.setExcludePaths(verifyRegexes(value, "badexcludelist", progress));
                    break;
                case "sessionManagement":
                    data.setSessionManagement(new SessionManagementData(value, progress));
                    break;
                default:
                    progress.warn(
                            Constant.messages.getString(
                                    "automation.error.options.unknown",
                                    AutomationEnvironment.AUTOMATION_CONTEXT_NAME,
                                    cdata.getKey().toString()));
            }
        }
        if (StringUtils.isEmpty(data.getName())) {
            progress.error(
                    Constant.messages.getString("automation.error.context.noname", contextData));
        }
        if (data.getUrls().isEmpty()) {
            progress.error(
                    Constant.messages.getString("automation.error.context.nourl", contextData));
        }
    }

    private void validateUrl(String url, AutomationProgress progress) {
        try {
            if (!url.contains("${")) {
                // Cannot validate urls containing envvars
                new URI(url, true);
            }
        } catch (URIException e) {
            progress.error(Constant.messages.getString("automation.error.context.badurl", url));
        }
    }

    private List<String> verifyRegexes(Object value, String key, AutomationProgress progress) {
        if (!(value instanceof ArrayList<?>)) {
            progress.error(Constant.messages.getString("automation.error.context." + key, value));
            return Collections.emptyList();
        }
        ArrayList<String> regexes = new ArrayList<>();
        for (Object regex : (ArrayList<?>) value) {
            String regexStr = regex.toString();
            regexes.add(regexStr);
            try {
                if (!regexStr.contains("${")) {
                    // Only validate the regex if it doesnt contain vars
                    Pattern.compile(regexStr);
                }
            } catch (PatternSyntaxException e) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.context.badregex",
                                regex.toString(),
                                e.getMessage()));
            }
        }
        return regexes;
    }

    public Context getContext() {
        return this.context;
    }

    public void addUrl(String url) {
        this.data.getUrls().add(url);
    }

    public List<String> getUrls() {
        return this.data.getUrls();
    }

    public Data getData() {
        return data;
    }

    public void setData(Data data) {
        this.data = data;
    }

    public void createContext(
            Session session, AutomationEnvironment env, AutomationProgress progress) {
        String contextName = env.replaceVars((getData().getName()));
        Context oldContext = session.getContext(contextName);
        if (oldContext != null) {
            session.deleteContext(oldContext);
        }
        this.context = session.getNewContext(contextName);
        for (String url : getData().getUrls()) {
            try {
                String urlWithEnvs = env.replaceVars(url);
                new URI(urlWithEnvs, true);
                this.context.addIncludeInContextRegex(urlWithEnvs + ".*");
            } catch (Exception e) {
                progress.error(Constant.messages.getString("automation.error.context.badurl", url));
            }
        }
        List<String> includePaths = getData().getIncludePaths();
        if (includePaths != null) {
            for (String path : includePaths) {
                String incRegex = env.replaceVars(path);
                if (!this.context.getIncludeInContextRegexs().contains(incRegex)) {
                    // The inc regex could have been included above, so no point duplicating it
                    this.context.addIncludeInContextRegex(incRegex);
                }
            }
        }
        List<String> excludePaths = getData().getExcludePaths();
        if (excludePaths != null) {
            for (String path : excludePaths) {
                this.context.addExcludeFromContextRegex(env.replaceVars(path));
            }
        }
        if (getData().getSessionManagement() != null) {
            initContextSessionManagement(progress);
        }
    }

    private void initContextSessionManagement(AutomationProgress progress) {
        switch (getData().getSessionManagement().getMethod().toLowerCase(Locale.ROOT)) {
            case SessionManagementData.METHOD_COOKIE:
                this.context.setSessionManagementMethod(
                        new CookieBasedSessionManagementMethod(context.getId()));
                break;
            case SessionManagementData.METHOD_HTTP:
                this.context.setSessionManagementMethod(new HttpAuthSessionManagementMethod());
                break;
            case SessionManagementData.METHOD_SCRIPT:
                File f = new File(getData().getSessionManagement().getScript());
                if (!f.exists() || !f.canRead()) {
                    progress.error(
                            Constant.messages.getString(
                                    "automation.error.env.sessionmgmt.script.bad",
                                    f.getAbsolutePath()));

                } else {
                    ScriptWrapper sw =
                            getScriptWrapper(
                                    f,
                                    getData().getSessionManagement().getScriptEngine(),
                                    progress);
                    ScriptBasedSessionManagementMethod smm =
                            getScriptBasedSessionManagementMethod(this.context.getId());
                    if (sw != null && smm != null) {
                        Map<String, String> paramValues = this.getParamValues(smm);
                        if (paramValues != null) {
                            paramValues.putAll(
                                    this.getData().getSessionManagement().getParameters());
                        }
                        setScriptWrapper(smm, sw);
                        this.context.setSessionManagementMethod(smm);

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
                                "automation.error.env.sessionmgmt.type.bad",
                                getData().getSessionManagement().getMethod()));
                break;
        }
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

    public static class Data {
        private String name;
        private List<String> urls = new ArrayList<>();
        private List<String> includePaths;
        private List<String> excludePaths;
        private SessionManagementData sessionManagement;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public List<String> getUrls() {
            return urls;
        }

        public void setUrls(List<String> urls) {
            this.urls = urls;
        }

        public List<String> getIncludePaths() {
            return includePaths;
        }

        public void setIncludePaths(List<String> includePaths) {
            this.includePaths = includePaths;
        }

        public List<String> getExcludePaths() {
            return excludePaths;
        }

        public void setExcludePaths(List<String> excludePaths) {
            this.excludePaths = excludePaths;
        }

        public SessionManagementData getSessionManagement() {
            return sessionManagement;
        }

        public void setSessionManagement(SessionManagementData sessionManagement) {
            this.sessionManagement = sessionManagement;
        }
    }

    public static class SessionManagementData extends AutomationData {

        public static final String METHOD_COOKIE = "cookie";
        public static final String METHOD_HTTP = "http";
        public static final String METHOD_SCRIPT = "script";

        private static List<String> validMethods =
                Arrays.asList(METHOD_COOKIE, METHOD_HTTP, METHOD_SCRIPT);

        private String method;
        private String script;
        private String scriptEngine;
        private Map<String, String> parameters = new LinkedHashMap<>();

        public SessionManagementData() {}

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
    }
}
