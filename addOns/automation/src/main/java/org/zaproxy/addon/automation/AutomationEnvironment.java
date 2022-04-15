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
import java.util.stream.Collectors;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.automation.gui.EnvironmentDialog;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;

public class AutomationEnvironment {

    public static final String AUTOMATION_CONTEXT_NAME = "Automation Context";

    private static final String YAML_FILE = "env.yaml";
    private static final Pattern varPattern = Pattern.compile("\\$\\{(.+?)\\}");

    private AutomationProgress progress;
    private List<ContextWrapper> contexts = new ArrayList<>();
    private Map<String, Object> jobData = new HashMap<>();
    private Map<String, String> combinedVars;
    private boolean created = false;
    private List<String> errors = new ArrayList<>();
    private List<String> warnings = new ArrayList<>();
    private AutomationPlan plan;

    private Data data = new Data();

    public AutomationEnvironment(AutomationProgress progress) {
        this.progress = progress;
    }

    public AutomationEnvironment(Map<?, ?> envData, AutomationProgress progress) {
        this(progress);
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
        this.progress.setOutputToStdout(this.getData().getParameters().getProgressToStdout());

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
            this.contexts.add(
                    new ContextWrapper((LinkedHashMap<?, ?>) contextObject, this, progress));
        }
    }

    public void addContext(Context context) {
        this.contexts.add(new ContextWrapper(context));
    }

    public void create(Session session, AutomationProgress progress) {

        this.created = true;
        this.combinedVars = null; // So that they are recreated
        boolean hasUrls = false;
        this.errors.clear();
        this.warnings.clear();

        for (ContextWrapper context : this.contexts) {
            context.createContext(session, this, progress);
            if (!context.getUrls().isEmpty()) {
                hasUrls = true;
            }
            if (this.isTimeToQuit()) {
                this.errors.addAll(progress.getErrors());
                this.warnings.addAll(progress.getWarnings());
                return;
            }
        }
        if (contexts.isEmpty()) {
            progress.error(Constant.messages.getString("automation.env.error.nocontexts"));
        } else if (!hasUrls) {
            progress.error(Constant.messages.getString("automation.env.error.nourls"));
        }
        this.errors.addAll(progress.getErrors());
        this.warnings.addAll(progress.getWarnings());
    }

    public String replaceVars(Object value) {
        if (value == null) {
            return null;
        }
        if (this.combinedVars == null) {
            this.combinedVars = new HashMap<>(this.getData().getVars());
            this.combinedVars.putAll(System.getenv());
        }
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

    public Map<String, String> replaceMapVars(Map<String, String> map) {
        Map<String, String> map2 = new HashMap<>();
        for (Entry<String, String> entry : map.entrySet()) {
            map2.put(entry.getKey(), replaceVars(entry.getValue()));
        }
        return map2;
    }

    protected void setProgress(AutomationProgress progress) {
        this.progress = progress;
        this.progress.setOutputToStdout(this.getData().getParameters().getProgressToStdout());
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

    public List<String> getAllUserNames() {
        List<String> userNames = new ArrayList<>();
        for (ContextWrapper context : contexts) {
            userNames.addAll(context.getUserNames());
        }

        return userNames;
    }

    public User getUser(String name) {
        for (ContextWrapper context : contexts) {
            User user = context.getUser(name);
            if (user != null) {
                return user;
            }
        }
        return null;
    }

    public String getSummary() {
        if (this.contexts.isEmpty()) {
            return Constant.messages.getString("automation.env.error.nocontexts");
        }
        return Constant.messages.getString(
                "automation.dialog.env.summary",
                this.contexts.stream()
                        .map(c -> c.getData().getName())
                        .collect(Collectors.toList())
                        .toString());
    }

    public boolean isCreated() {
        return created;
    }

    public boolean hasErrors() {
        return !this.errors.isEmpty();
    }

    public boolean hasWarnings() {
        return !this.warnings.isEmpty();
    }

    public List<String> getErrors() {
        return errors;
    }

    public List<String> getWarnings() {
        return warnings;
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
        private boolean progressToStdout = true;

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
