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
package org.zaproxy.zap.extension.scripts.automation;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.automation.AutomationEventPublisher;
import org.zaproxy.addon.automation.AutomationPlan;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.authentication.ScriptBasedAuthenticationMethodType;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptEventListener;
import org.zaproxy.zap.extension.script.ScriptWrapper;

public class ExtensionScriptAutomation extends ExtensionAdaptor {

    public static final String NAME = "ExtensionScriptAutomation";
    private static final String RESOURCES_DIR = "/org/zaproxy/zap/extension/scripts/resources/";

    private ScriptJob job;

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionScript.class, ExtensionAutomation.class);

    private ExtensionAutomation extAuto;
    private ExtensionScript extensionScript;
    private ScriptErrorHandler scriptErrorHandler;

    public ExtensionScriptAutomation() {
        super(NAME);
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        extAuto = getExtension(ExtensionAutomation.class);
        job = new ScriptJob();
        extAuto.registerAutomationJob(job);

        extensionScript = getExtension(ExtensionScript.class);
        scriptErrorHandler = new ScriptErrorHandler();
        extensionScript.addListener(scriptErrorHandler);

        ZAP.getEventBus()
                .registerConsumer(
                        scriptErrorHandler,
                        AutomationEventPublisher.getPublisher().getPublisherName(),
                        AutomationEventPublisher.PLAN_STARTED,
                        AutomationEventPublisher.PLAN_FINISHED);
    }

    private static <T extends Extension> T getExtension(Class<T> clazz) {
        return Control.getSingleton().getExtensionLoader().getExtension(clazz);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        extAuto.unregisterAutomationJob(job);

        extensionScript.removeListener(scriptErrorHandler);
        ZAP.getEventBus().unregisterConsumer(scriptErrorHandler);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("scripts.automation.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("scripts.automation.name");
    }

    public static String getResourceAsString(String name) {
        try (InputStream in =
                ExtensionScriptAutomation.class.getResourceAsStream(RESOURCES_DIR + name)) {
            return new BufferedReader(new InputStreamReader(in))
                            .lines()
                            .collect(Collectors.joining("\n"))
                    + "\n";
        } catch (Exception e) {
            CommandLine.error(
                    Constant.messages.getString(
                            "scripts.automation.error.nofile", RESOURCES_DIR + name));
        }
        return "";
    }

    private class ScriptErrorHandler implements ScriptEventListener, EventConsumer {

        private List<AutomationPlan> runningPlans = Collections.synchronizedList(new ArrayList<>());

        @Override
        public void refreshScript(ScriptWrapper script) {
            // Nothing to do.
        }

        @Override
        public void scriptAdded(ScriptWrapper script, boolean display) {
            // Nothing to do.
        }

        @Override
        public void scriptRemoved(ScriptWrapper script) {
            // Nothing to do.
        }

        @Override
        public void preInvoke(ScriptWrapper script) {
            // Nothing to do.
        }

        @Override
        public void scriptChanged(ScriptWrapper script) {
            // Nothing to do.
        }

        @Override
        public void scriptError(ScriptWrapper script) {
            if (ExtensionScript.TYPE_STANDALONE.equals(script.getTypeName())
                    || ScriptBasedAuthenticationMethodType.SCRIPT_TYPE_AUTH.equals(
                            script.getTypeName())) {
                // Errors of stand alone scripts are handled directly by the job.
                // Authentication script errors are handled as auth failures.
                return;
            }

            synchronized (runningPlans) {
                runningPlans.forEach(
                        plan ->
                                plan.getProgress()
                                        .error(
                                                Constant.messages.getString(
                                                        "scripts.automation.error.script",
                                                        script.getName(),
                                                        script.getLastErrorDetails())));
            }
        }

        @Override
        public void scriptSaved(ScriptWrapper script) {
            // Nothing to do.
        }

        @Override
        public void templateAdded(ScriptWrapper script, boolean display) {
            // Nothing to do.
        }

        @Override
        public void templateRemoved(ScriptWrapper script) {
            // Nothing to do.
        }

        @Override
        public void eventReceived(Event event) {
            int planId =
                    Integer.parseInt(event.getParameters().get(AutomationEventPublisher.PLAN_ID));
            AutomationPlan plan = extAuto.getPlan(planId);
            if (AutomationEventPublisher.PLAN_STARTED.equals(event.getEventType())) {
                runningPlans.add(plan);
            } else {
                runningPlans.remove(plan);
            }
        }
    }
}
