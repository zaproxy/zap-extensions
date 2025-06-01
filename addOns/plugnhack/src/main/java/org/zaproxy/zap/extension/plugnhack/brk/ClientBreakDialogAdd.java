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
import org.zaproxy.zap.extension.plugnhack.ClientMessage;
import org.zaproxy.zap.extension.plugnhack.ExtensionPlugNHack;

@SuppressWarnings("serial")
public class ClientBreakDialogAdd extends ClientBreakDialog {

    private static final long serialVersionUID = 1L;
    private ActionListener actionListenerCancel;
    private ActionListener actionListenerSubmit;

    public ClientBreakDialogAdd(
            ExtensionPlugNHack extension, ClientBreakpointsUiManagerInterface breakPointsManager)
            throws HeadlessException {
        super(extension, breakPointsManager);
    }

    @Override
    protected String getBtnSubmitText() {
        return Constant.messages.getString("brk.add.button.add");
    }

    @Override
    protected String getDialogTitle() {
        return Constant.messages.getString("brk.add.title");
    }

    @Override
    protected ActionListener getActionListenerCancel() {
        if (actionListenerCancel == null) {
            actionListenerCancel = e -> dispose();
        }
        return actionListenerCancel;
    }

    @Override
    protected ActionListener getActionListenerSubmit() {
        if (actionListenerSubmit == null) {
            actionListenerSubmit =
                    evt -> {
                        try {
                            breakPointsManager.addBreakpoint(getClientBreakpointMessage());
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

    /**
     * Resets fields of dialog to default value or to values set in given parameter.
     *
     * @param aMessage
     */
    public void setMessage(ClientMessage msg) {
        resetDialogValues();
        setDialogValues(msg.getType(), msg.getClientId(), null);
    }
}
