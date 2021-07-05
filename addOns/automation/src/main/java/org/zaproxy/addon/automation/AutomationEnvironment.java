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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.model.Context;

public class AutomationEnvironment {

    public static final String AUTOMATION_CONTEXT_NAME = "Automation Context";

    private static final String YAML_FILE = "env.yaml";
    private static final Pattern varPattern = Pattern.compile("\\$\\{(.+?)\\}");

    private AutomationProgress progress;
    private List<ContextWrapper> contexts = new ArrayList<>();
    private boolean failOnError = true;
    private boolean failOnWarning = false;
    private Map<String, Object> jobData = new HashMap<>();
    private Map<String, String> vars = new HashMap<>(System.getenv());

    public AutomationEnvironment(
            LinkedHashMap<?, ?> envData, AutomationProgress progress, Session session) {
        this.progress = progress;
        if (envData == null) {
            progress.error(Constant.messages.getString("automation.error.env.missing"));
            return;
        }

        LinkedHashMap<?, ?> configVars = (LinkedHashMap<?, ?>) envData.get("vars");
        if (configVars != null) {
            for (Entry<?, ?> configVar : configVars.entrySet()) {
                if (vars.containsKey(configVar.getKey().toString())) {
                    continue;
                }
                vars.put(configVar.getKey().toString(), configVar.getValue().toString());
            }
            for (Entry<String, String> unresolvedVar : vars.entrySet()) {
                vars.put(unresolvedVar.getKey(), replaceVars(unresolvedVar.getValue()));
            }
        }

        LinkedHashMap<?, ?> params = (LinkedHashMap<?, ?>) envData.get("parameters");
        if (params != null) {
            for (Entry<?, ?> param : params.entrySet()) {
                switch (param.getKey().toString()) {
                    case "failOnError":
                        failOnError = Boolean.parseBoolean(param.getValue().toString());
                        break;
                    case "failOnWarning":
                        failOnWarning = Boolean.parseBoolean(param.getValue().toString());
                        break;
                    case "progressToStdout":
                        progress.setOutputToStdout(
                                Boolean.parseBoolean(param.getValue().toString()));
                        break;
                    default:
                        progress.warn(
                                Constant.messages.getString(
                                        "automation.error.options.unknown",
                                        AUTOMATION_CONTEXT_NAME,
                                        param.getKey().toString()));
                }
            }
        }

        Object contextsObject = envData.get("contexts");
        if (contextsObject == null) {
            progress.error(Constant.messages.getString("automation.error.env.nocontexts", envData));
            return;
        }
        if (!(contextsObject instanceof ArrayList)) {
            progress.error(
                    Constant.messages.getString(
                            "automation.error.env.badcontexts", contextsObject));
            return;
        }
        for (Object contextObject : ((ArrayList<?>) contextsObject).toArray()) {
            ContextWrapper context = parseContextData(contextObject, progress, session);
            if (context != null) {
                this.contexts.add(context);
                if (this.isTimeToQuit()) {
                    return;
                }
            }
        }
    }

    public ContextWrapper parseContextData(
            Object contextObject, AutomationProgress progress, Session session) {
        if (!(contextObject instanceof LinkedHashMap)) {
            progress.error(
                    Constant.messages.getString("automation.error.env.badcontext", contextObject));
            return null;
        }
        String name = null;
        List<String> urls = new ArrayList<>();
        ArrayList<?> includeRegexes = null;
        ArrayList<?> excludeRegexes = null;
        for (Entry<?, ?> cdata : ((LinkedHashMap<?, ?>) contextObject).entrySet()) {
            Object value = cdata.getValue();
            if (value == null) {
                continue;
            }
            switch (cdata.getKey().toString()) {
                case "name":
                    name = replaceVars(value);
                    break;
                case "urls":
                    if (!(value instanceof ArrayList)) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.context.badurlslist", value));

                    } else {
                        ArrayList<?> urlList = (ArrayList<?>) value;
                        for (Object urlObj : urlList) {
                            try {
                                String url = replaceVars(urlObj);
                                new URI(url, true);
                                urls.add(url);
                            } catch (URIException e) {
                                progress.error(
                                        Constant.messages.getString(
                                                "automation.error.context.badurl", urlObj));
                            }
                        }
                    }
                    break;
                case "url":
                    // For backwards compatibility
                    try {
                        String url = replaceVars(value);
                        new URI(url, true);
                        urls.add(url);
                        progress.warn(
                                Constant.messages.getString(
                                        "automation.error.context.url.deprecated"));
                    } catch (URIException e) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.context.badurl", value.toString()));
                    }
                    break;
                case "includePaths":
                    includeRegexes = verifyRegexes(value, "badincludelist", progress);
                    break;
                case "excludePaths":
                    excludeRegexes = verifyRegexes(value, "badexcludelist", progress);
                    break;
                default:
                    progress.warn(
                            Constant.messages.getString(
                                    "automation.error.options.unknown",
                                    AUTOMATION_CONTEXT_NAME,
                                    cdata.getKey().toString()));
            }
        }
        if (name == null) {
            progress.error(
                    Constant.messages.getString("automation.error.context.noname", contextObject));
            return null;
        }
        if (urls.isEmpty()) {
            progress.error(
                    Constant.messages.getString("automation.error.context.nourl", contextObject));
            return null;
        }
        Context context = session.getNewContext(name);
        if (includeRegexes != null) {
            for (Object regex : includeRegexes) {
                context.addIncludeInContextRegex(replaceVars(regex.toString()));
            }
        }
        if (excludeRegexes != null) {
            for (Object regex : excludeRegexes) {
                context.addExcludeFromContextRegex(replaceVars(regex.toString()));
            }
        }
        ContextWrapper wrapper = new ContextWrapper(context);
        for (String u : urls) {
            context.addIncludeInContextRegex(u + ".*");
            wrapper.addUrl(u);
        }
        return wrapper;
    }

    private static ArrayList<?> verifyRegexes(
            Object value, String key, AutomationProgress progress) {
        if (!(value instanceof ArrayList)) {
            progress.error(Constant.messages.getString("automation.error.context." + key, value));
            return null;
        }
        ArrayList<?> regexes = (ArrayList<?>) value;
        for (Object regex : regexes) {
            try {
                Pattern.compile(regex.toString());
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

    public String replaceVars(Object value) {
        String text = value.toString();
        Matcher matcher = varPattern.matcher(text);
        StringBuffer sb = new StringBuffer();

        while (matcher.find()) {
            String val = this.getVars().get(matcher.group(1));
            if (val != null) {
                matcher.appendReplacement(sb, "");
                sb.append(val);
            } else {
                progress.warn(
                        Constant.messages.getString(
                                "automation.error.env.novar", matcher.group(1)));
            }
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    public static String getConfigFileData() {
        return ExtensionAutomation.getResourceAsString(YAML_FILE);
    }

    public static String getTemplateFileData() {
        return ExtensionAutomation.getResourceAsString(YAML_FILE);
    }

    public List<ContextWrapper> getContextWrappers() {
        return contexts;
    }

    public List<Context> getContexts() {
        return contexts.stream().map(ContextWrapper::getContext).collect(Collectors.toList());
    }

    public Map<String, String> getVars() {
        return vars;
    }

    public String getVar(String name) {
        return vars.get(name);
    }

    public ContextWrapper getContextWrapper(String name) {
        if (name == null || name.length() == 0) {
            return getDefaultContextWrapper();
        }
        for (ContextWrapper context : contexts) {
            if (name.equals(context.getContext().getName())) {
                return context;
            }
        }
        return null;
    }

    public Context getContext(String name) {
        ContextWrapper wrapper = this.getContextWrapper(name);
        if (wrapper != null) {
            return wrapper.getContext();
        }
        return null;
    }

    /**
     * Use the methods which return a ContextWrapper and then access this list of URLs from the
     * wrappers.
     *
     * @deprecated
     */
    @Deprecated
    public String getUrlStringForContext(Context context) {
        if (context != null) {
            String firstRegex = context.getIncludeInContextRegexs().get(0);
            return firstRegex.substring(0, firstRegex.length() - 2);
        }
        return null;
    }

    public ContextWrapper getDefaultContextWrapper() {
        return contexts.get(0);
    }

    public Context getDefaultContext() {
        return contexts.get(0).getContext();
    }

    public void addJobData(String key, Object data) {
        this.jobData.put(key, data);
    }

    public Object getJobData(String key) {
        return this.jobData.get(key);
    }

    public Set<String> getJobDataKeys() {
        return this.jobData.keySet();
    }

    public boolean isFailOnError() {
        return failOnError;
    }

    public boolean isFailOnWarning() {
        return failOnWarning;
    }

    public boolean isTimeToQuit() {
        return (failOnError && progress.hasErrors()) || (failOnWarning && progress.hasWarnings());
    }
}
