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
package org.zaproxy.addon.requester;

import java.awt.EventQueue;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.view.AbstractFrame;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.utils.DisplayUtils;

/** A dialogue that contains an editor of a {@link Message} and allows to send it. */
public abstract class MessageEditorDialog extends AbstractFrame {

    private static final long serialVersionUID = 1L;

    private final MessageEditorPanel panel;

    /**
     * Constructs a {@code MessageEditorDialog} with the given panel.
     *
     * @param panel the panel with the editor.
     */
    protected MessageEditorDialog(MessageEditorPanel panel) {
        super();

        this.panel = panel;

        addWindowListener(
                new WindowAdapter() {

                    @Override
                    public void windowClosed(WindowEvent e) {
                        panel.saveConfig();
                    }

                    @Override
                    public void windowClosing(WindowEvent e) {
                        windowClosed(e);
                    }
                });

        setPreferredSize(DisplayUtils.getScaledDimension(700, 800));
        setContentPane(panel);
    }

    /**
     * Loads the dialogue into ZAP.
     *
     * <p>Should be called when the corresponding {@link Extension#hook extension is hooked}.
     *
     * <p>By default it adds a {@link SessionChangedListener} to respect the selected {@link Mode}
     * and reset the panel when the session changes.
     *
     * @param extensionHook the extension hook.
     * @see #unload()
     */
    public void load(ExtensionHook extensionHook) {
        extensionHook.addSessionListener(new SessionChangedListenerImpl());
    }

    /**
     * Unloads the dialogue from ZAP.
     *
     * <p>Unloads the panel, hides and disposes the dialogue.
     *
     * @see #load(ExtensionHook)
     */
    public void unload() {
        panel.unload();
        setVisible(false);
        dispose();
    }

    /** The listener to respect the mode and clear the panel on session changes. */
    private class SessionChangedListenerImpl implements SessionChangedListener {

        @Override
        public void sessionChanged(Session session) {
            EventQueue.invokeLater(panel::reset);
        }

        @Override
        public void sessionAboutToChange(Session session) {
            // Nothing to do.
        }

        @Override
        public void sessionScopeChanged(Session session) {
            // Nothing to do.
        }

        @Override
        public void sessionModeChanged(Mode mode) {
            EventQueue.invokeLater(() -> setEnabled(mode != Mode.safe));
        }
    }
}
