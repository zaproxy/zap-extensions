/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.zap.extension.sequence.automation;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.extension.ascan.ExtensionActiveScan;
import org.zaproxy.zap.extension.sequence.ExtensionSequence;
import org.zaproxy.zap.extension.zest.ExtensionZest;

public class ExtensionSequenceAutomation extends ExtensionAdaptor {

    public static final String NAME = "ExtensionSequenceAutomation";
    public static final String STATS_PREFIX = "stats.sequence.automation.";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionAutomation.class, ExtensionExim.class, ExtensionSequence.class);

    private SequenceImportJob importJob;
    private SequenceActiveScanJob ascanJob;

    public ExtensionSequenceAutomation() {
        super(NAME);
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        ExtensionAutomation extAuto = getExtension(ExtensionAutomation.class);
        ExtensionSequence extSeq = getExtension(ExtensionSequence.class);
        importJob =
                new SequenceImportJob(
                        extSeq.getScriptType(),
                        getExtension(ExtensionExim.class),
                        getExtension(ExtensionZest.class));
        extAuto.registerAutomationJob(importJob);

        ascanJob = new SequenceActiveScanJob(extSeq, getExtension(ExtensionActiveScan.class));
        extAuto.registerAutomationJob(ascanJob);

        extensionHook.addSessionListener(new SessionChangedListenerImpl());
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
        ExtensionAutomation extAuto = getExtension(ExtensionAutomation.class);

        extAuto.unregisterAutomationJob(importJob);
        extAuto.unregisterAutomationJob(ascanJob);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("sequence.automation.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("sequence.automation.name");
    }

    private static class SessionChangedListenerImpl implements SessionChangedListener {

        @Override
        public void sessionScopeChanged(Session session) {
            // Nothing to do.
        }

        @Override
        public void sessionModeChanged(Mode mode) {
            // Nothing to do.
        }

        @Override
        public void sessionChanged(Session session) {
            // Nothing to do.
        }

        @Override
        public void sessionAboutToChange(Session session) {
            SequenceActiveScanJob.clearJobResultData();
        }
    }
}
