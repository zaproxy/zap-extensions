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
package org.zaproxy.addon.requester.internal;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.requester.PopupMenuResendMessage;
import org.zaproxy.zap.extension.requester.ExtensionRequester;
import org.zaproxy.zap.extension.requester.ManualHttpRequestEditorPanel;

public class ResendHttpMessageEditorDialog extends AbstractHttpMessageEditorDialog {

    private static final long serialVersionUID = 1L;

    public ResendHttpMessageEditorDialog(ManualHttpRequestEditorPanel panel) {
        super("requester.resend.dialog.title", panel);
    }

    @Override
    public void load(ExtensionHook extensionHook) {
        super.load(extensionHook);

        PopupMenuResendMessage popupMenuResendMessage =
                new PopupMenuResendMessage(
                        Constant.messages.getString("requester.resend.popup"),
                        ExtensionRequester.getManualIcon(),
                        msg -> {
                            getPanel().setMessage(msg);
                            setVisible(true);
                        });
        extensionHook.getHookMenu().addPopupMenuItem(popupMenuResendMessage);
    }
}
