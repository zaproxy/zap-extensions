/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.llm.automation;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.llm.ExtensionLlm;

/** Adds Automation Framework support to the LLM add-on. */
public class ExtensionLlmAutomation extends ExtensionAdaptor {

    public static final String NAME = "ExtensionLlmAutomation";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionLlm.class, ExtensionAutomation.class);

    private LlmConfigJob configJob;

    public ExtensionLlmAutomation() {
        super(NAME);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        configJob = new LlmConfigJob();
        getExtensionAutomation().registerAutomationJob(configJob);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        getExtensionAutomation().unregisterAutomationJob(configJob);
    }

    private static ExtensionAutomation getExtensionAutomation() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionAutomation.class);
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("llm.automation.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("llm.automation.desc");
    }
}
