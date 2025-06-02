/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.plugnhack.brk;

import java.awt.HeadlessException;
import java.awt.event.ActionListener;
import java.util.regex.PatternSyntaxException;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.plugnhack.ExtensionPlugNHack;

@SuppressWarnings("serial")
public class ClientBreakDialogEdit extends ClientBreakDialog {
    private static final long serialVersionUID = 1L;

    private ActionListener actionListenerCancel;
    private ActionListener actionListenerSubmit;

    private ClientBreakpointMessage breakpoint;

    public ClientBreakDialogEdit(
            ExtensionPlugNHack extension, ClientBreakpointsUiManagerInterface breakPointsManager)
            throws HeadlessException {
        super(extension, breakPointsManager);
    }

    @Override
    protected String getBtnSubmitText() {
        return Constant.messages.getString("brk.edit.button.save");
    }

    @Override
    protected String getDialogTitle() {
        return Constant.messages.getString("brk.edit.title");
    }

    @Override
    protected ActionListener getActionListenerCancel() {
        if (actionListenerCancel == null) {
            actionListenerCancel =
                    e -> {
                        breakpoint = null;
                        dispose();
                    };
        }
        return actionListenerCancel;
    }

    @Override
    protected ActionListener getActionListenerSubmit() {
        if (actionListenerSubmit == null) {
            actionListenerSubmit =
                    evt -> {
                        try {
                            breakPointsManager.editBreakpoint(
                                    breakpoint, getClientBreakpointMessage());
                            breakpoint = null;
                            dispose();
                        } catch (PatternSyntaxException e) {
                            // show popup
                            View.getSingleton()
                                    .showWarningDialog(
                                            Constant.messages.getString(
                                                    "plugnhack.invalidpattern"));
                            return;
                        }
                    };
        }
        return actionListenerSubmit;
    }

    public void setBreakpoint(ClientBreakpointMessage breakpoint) {
        resetDialogValues();

        this.breakpoint = breakpoint;
        setDialogValues(
                breakpoint.getMessageType(),
                breakpoint.getClient(),
                breakpoint.getPayloadPattern());
    }
}
