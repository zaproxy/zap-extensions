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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map.Entry;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.model.Context;

public class AutomationEnvironment {

    public static final String AUTOMATION_CONTEXT_NAME = "Automation Context";

    private static final String YAML_FILE = "env.yaml";

    private AutomationProgress progress;
    private List<Context> contexts = new ArrayList<Context>();;
    private boolean failOnError = true;
    private boolean failOnWarning = false;

    public AutomationEnvironment(
            LinkedHashMap<?, ?> envData, AutomationProgress progress, Session session) {
        this.progress = progress;
        if (envData == null) {
            progress.error(Constant.messages.getString("automation.error.env.missing"));
            return;
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
            Context context = parseContextData(contextObject, progress, session);
            if (context != null) {
                this.contexts.add(context);
                if (this.isTimeToQuit()) {
                    return;
                }
            }
        }
    }

    public static Context parseContextData(
            Object contextObject, AutomationProgress progress, Session session) {
        if (!(contextObject instanceof LinkedHashMap)) {
            progress.error(
                    Constant.messages.getString("automation.error.env.badcontext", contextObject));
            return null;
        }
        String name = null;
        URL url = null;
        for (Entry<?, ?> cdata : ((LinkedHashMap<?, ?>) contextObject).entrySet()) {
            Object value = cdata.getValue();
            if (value == null) {
                continue;
            }
            switch (cdata.getKey().toString()) {
                case "name":
                    name = value.toString();
                    break;
                case "url":
                    try {
                        url = new URL(value.toString());
                    } catch (MalformedURLException e) {
                        progress.error(
                                Constant.messages.getString(
                                        "automation.error.context.badurl", value.toString()));
                    }
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
        if (url == null) {
            progress.error(
                    Constant.messages.getString("automation.error.context.nourl", contextObject));
            return null;
        }
        Context context = session.getNewContext(name);
        context.addIncludeInContextRegex(url + ".*");
        return context;
    }

    public static String getConfigFileData() {
        return ExtensionAutomation.getResourceAsString(YAML_FILE);
    }

    public static String getTemplateFileData() {
        return ExtensionAutomation.getResourceAsString(YAML_FILE);
    }

    public List<Context> getContexts() {
        return contexts;
    }

    public Context getContext(String name) {
        if (name == null || name.length() == 0) {
            return getDefaultContext();
        }
        for (Context context : contexts) {
            if (name.equals(context.getName())) {
                return context;
            }
        }
        return null;
    }

    public String getUrlStringForContext(Context context) {
        if (context != null) {
            String firstRegex = context.getIncludeInContextRegexs().get(0);
            return firstRegex.substring(0, firstRegex.length() - 2);
        }
        return null;
    }

    public Context getDefaultContext() {
        return contexts.get(0);
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
