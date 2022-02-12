/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.commonlib;

import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.commonlib.ui.ProgressPanel;

public class ExtensionCommonlib extends ExtensionAdaptor {

    private ProgressPanel progressPanel;

    @Override
    public void hook(ExtensionHook extensionHook) {
        if (hasView()) {
            extensionHook.getHookView().addStatusPanel(getProgressPanel());
            extensionHook.addSessionListener(new SessionChangedListenerImpl());
        }
    }

    public ProgressPanel getProgressPanel() {
        if (progressPanel == null) {
            progressPanel = new ProgressPanel(getView());
        }
        return progressPanel;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    private class SessionChangedListenerImpl implements SessionChangedListener {

        @Override
        public void sessionChanged(Session session) {
            // Nothing to do
        }

        @Override
        public void sessionAboutToChange(Session session) {
            getProgressPanel().clearAndDispose();
        }

        @Override
        public void sessionScopeChanged(Session session) {
            // Nothing to do
        }

        @Override
        public void sessionModeChanged(Mode mode) {
            // Nothing to do
        }
    }
}
