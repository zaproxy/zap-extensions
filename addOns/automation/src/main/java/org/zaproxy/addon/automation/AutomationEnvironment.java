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
import org.zaproxy.addon.automation.gui.EnvironmentDialog;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.model.Context;

public class AutomationEnvironment {

    public static final String AUTOMATION_CONTEXT_NAME = "Automation Context";

    private static final String YAML_FILE = "env.yaml";
    private static final Pattern varPattern = Pattern.compile("\\$\\{(.+?)\\}");

    private AutomationProgress progress;
    private List<ContextWrapper> contexts = new ArrayList<>();
    private Map<String, Object> jobData = new HashMap<>();
    private Map<String, String> combinedVars;
    private boolean created = false;
    private boolean hasErrors = false;
    private boolean hasWarnings = false;
    private AutomationPlan plan;

    private Data data = new Data();

    public AutomationEnvironment(LinkedHashMap<?, ?> envData, AutomationProgress progress) {
        this.progress = progress;
        if (envData == null) {
            progress.error(Constant.messages.getString("automation.error.env.missing"));
            return;
        }

        LinkedHashMap<?, ?> configVars = (LinkedHashMap<?, ?>) envData.get("vars");
        if (configVars != null) {
            for (Entry<?, ?> configVar : configVars.entrySet()) {
                this.getData()
                        .getVars()
                        .put(configVar.getKey().toString(), configVar.getValue().toString());
            }
        }

        LinkedHashMap<?, ?> params = (LinkedHashMap<?, ?>) envData.get("parameters");
        JobUtils.applyParamsToObject(
                params,
                this.getData().getParameters(),
                Constant.messages.getString("automation.env.name"),
                null,
                progress);

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
        ArrayList<?> contextData = (ArrayList<?>) contextsObject;
        for (Object contextObject : contextData.toArray()) {
            if (!(contextObject instanceof LinkedHashMap)) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.env.badcontext", contextObject));
                return;
            }
            ContextWrapper cdw = parseContextData((LinkedHashMap<?, ?>) contextObject, progress);
            if (cdw != null) {
                this.contexts.add(cdw);
            }
        }
    }

    public ContextWrapper parseContextData( // TODO move into constructor?
            LinkedHashMap<?, ?> contextData, AutomationProgress progress) {
        String name = null;
        List<String> urls = new ArrayList<>();
        ArrayList<?> includeRegexes = null;
        ArrayList<?> excludeRegexes = null;
        for (Entry<?, ?> cdata : contextData.entrySet()) {
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
                                String url = urlObj.toString();
                                if (!url.contains("${")) {
                                    // Cannot validate urls containing envvars
                                    new URI(url, true);
                                }
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
                        String url = value.toString();
                        if (!url.contains("${")) {
                            // Cannot validate urls containing envvars
                            new URI(url, true);
                        }
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
                    Constant.messages.getString("automation.error.context.noname", contextData));
            return null;
        }
        if (urls.isEmpty()) {
            progress.error(
                    Constant.messages.getString("automation.error.context.nourl", contextData));
            return null;
        }
        ContextWrapper.Data data = new ContextWrapper.Data();
        data.setName(name);
        data.setUrls(urls);

        List<String> incUrls = new ArrayList<>();
        if (includeRegexes != null) {
            for (Object regex : includeRegexes) {
                incUrls.add(regex.toString());
            }
        }
        data.setIncludePaths(incUrls);
        List<String> excUrls = new ArrayList<>();
        if (excludeRegexes != null) {
            for (Object regex : excludeRegexes) {
                excUrls.add(regex.toString());
            }
        }
        data.setExcludePaths(excUrls);
        return new ContextWrapper(data);
    }

    public void create(Session session, AutomationProgress progress) {

        this.created = true;
        this.combinedVars = new HashMap<>(System.getenv());
        this.combinedVars.putAll(this.getData().getVars());

        for (ContextWrapper context : this.contexts) {
            context.createContext(session, this);
            if (this.isTimeToQuit()) {
                this.hasErrors = progress.hasErrors();
                this.hasWarnings = progress.hasWarnings();
                return;
            }
        }
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
            String val = this.combinedVars.get(matcher.group(1));
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

    public void addContext(ContextWrapper.Data contextData) {
        this.contexts.add(new ContextWrapper(contextData));
    }

    public List<ContextWrapper> getContextWrappers() {
        return contexts;
    }

    public void setContexts(List<ContextWrapper> contexts) {
        this.contexts = contexts;
    }

    public List<Context> getContexts() {
        return contexts.stream().map(ContextWrapper::getContext).collect(Collectors.toList());
    }

    public List<String> getContextNames() {
        return contexts.stream()
                .map(ContextWrapper::getData)
                .collect(Collectors.toList())
                .stream()
                .map(ContextWrapper.Data::getName)
                .collect(Collectors.toList());
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

    public boolean isCreated() {
        return created;
    }

    public boolean hasErrors() {
        return hasErrors;
    }

    public boolean hasWarnings() {
        return hasWarnings;
    }

    public AutomationPlan getPlan() {
        return plan;
    }

    public void setPlan(AutomationPlan plan) {
        this.plan = plan;
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
        if (contexts.isEmpty()) {
            return null;
        }
        return contexts.get(0);
    }

    public Context getDefaultContext() {
        if (contexts.isEmpty()) {
            return null;
        }
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
        return this.getData().getParameters().getFailOnError();
    }

    public boolean isFailOnWarning() {
        return this.getData().getParameters().getFailOnWarning();
    }

    public boolean isTimeToQuit() {
        return (isFailOnError() && progress.hasErrors())
                || (isFailOnWarning() && progress.hasWarnings());
    }

    public void showDialog() {
        new EnvironmentDialog(this).setVisible(true);
    }

    public Data getData() {
        // The contexts are maintained locally
        this.data.setContexts(
                this.contexts.stream().map(ContextWrapper::getData).collect(Collectors.toList()));
        return this.data;
    }

    public static class Data extends AutomationData {
        private List<ContextWrapper.Data> contexts = new ArrayList<>();
        private Parameters parameters;
        private Map<String, String> vars = new LinkedHashMap<>();

        public Data() {
            setParameters(new Parameters());
        }

        public List<ContextWrapper.Data> getContexts() {
            return contexts;
        }

        public void setContexts(List<ContextWrapper.Data> contexts) {
            this.contexts = contexts;
        }

        public Parameters getParameters() {
            return parameters;
        }

        public void setParameters(Parameters parameters) {
            this.parameters = parameters;
        }

        public Map<String, String> getVars() {
            return vars;
        }

        public void setVars(Map<String, String> vars) {
            this.vars = vars;
        }
    }

    public static class Parameters extends AutomationData {
        private boolean failOnError = true;
        private boolean failOnWarning;
        private boolean progressToStdout;

        public Parameters() {}

        public Parameters(boolean failOnError, boolean failOnWarning, boolean progressToStdout) {
            super();
            this.failOnError = failOnError;
            this.failOnWarning = failOnWarning;
            this.progressToStdout = progressToStdout;
        }

        public boolean getFailOnError() {
            return failOnError;
        }

        public boolean getFailOnWarning() {
            return failOnWarning;
        }

        public boolean getProgressToStdout() {
            return progressToStdout;
        }

        public void setFailOnError(boolean failOnError) {
            this.failOnError = failOnError;
        }

        public void setFailOnWarning(boolean failOnWarning) {
            this.failOnWarning = failOnWarning;
        }

        public void setProgressToStdout(boolean progressToStdout) {
            this.progressToStdout = progressToStdout;
        }
    }
}
