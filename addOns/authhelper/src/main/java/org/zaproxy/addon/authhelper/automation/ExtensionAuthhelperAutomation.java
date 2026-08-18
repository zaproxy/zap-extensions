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
package org.zaproxy.addon.authhelper.automation;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.authhelper.AuthenticationDiagnostics;
import org.zaproxy.addon.authhelper.ExtensionAuthhelper;
import org.zaproxy.addon.automation.ExtensionAutomation;

public class ExtensionAuthhelperAutomation extends ExtensionAdaptor {

    public static final String NAME = "ExtensionAuthhelperAutomation";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionAuthhelper.class, ExtensionAutomation.class);

    private DiagnosticsJob diagnosticsJob;

    public ExtensionAuthhelperAutomation() {
        super(NAME);
        setI18nPrefix("authhelper");
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        diagnosticsJob = new DiagnosticsJob();
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionAutomation.class)
                .registerAutomationJob(diagnosticsJob);
        AuthenticationDiagnostics.setFlushHook(this::flushRunningPlans);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        AuthenticationDiagnostics.setFlushHook(null);
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionAutomation.class)
                .unregisterAutomationJob(diagnosticsJob);
    }

    private void flushRunningPlans() {
        Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionAutomation.class)
                .getRunningPlans()
                .forEach(DiagnosticsJob::flush);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("authhelper.automation.ext.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("authhelper.automation.ext.name");
    }
}
