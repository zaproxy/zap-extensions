/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.internal.ui.diags;

import java.awt.BorderLayout;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.authhelper.AuthhelperParam;
import org.zaproxy.addon.authhelper.ExtensionAuthhelper;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.TabbedPanel2;

public class AuthDiagsPanel extends AbstractPanel {

    private static final long serialVersionUID = 1L;

    private final AllDiagnosticsPanel allDiagsPanel;
    private final TabbedPanel2 tabbedPane;

    public AuthDiagsPanel(AuthhelperParam options, ExtensionHook hook) {
        hook.addSessionListener(
                new SessionChangedListener() {

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
                        refresh();
                    }

                    @Override
                    public void sessionAboutToChange(Session session) {
                        clear();
                    }
                });

        setName(Constant.messages.getString("authhelper.authdiags.panel.title"));
        setIcon(
                DisplayUtils.getScaledIcon(
                        getClass()
                                .getResource(
                                        ExtensionAuthhelper.RESOURCES_DIR
                                                + "images/hand-padlock.png")));

        tabbedPane = new TabbedPanel2();
        allDiagsPanel = new AllDiagnosticsPanel(options, tabbedPane);

        setLayout(new BorderLayout());
        add(tabbedPane);

        hook.getHookView().addStatusPanel(this);
    }

    public void refresh() {
        clear();

        allDiagsPanel.refresh();
    }

    public void clear() {
        allDiagsPanel.clear();
    }
}
