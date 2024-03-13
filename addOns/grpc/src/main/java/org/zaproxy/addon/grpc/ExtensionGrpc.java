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
package org.zaproxy.addon.grpc;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionGrpc extends ExtensionAdaptor {

    public static final String NAME = "ExtensionGrpc";

    private ZapMenuItem protoBufToolsMenuItem;

    private ProtoBufEditorDialog protoBufEditorDialog;

    public ExtensionGrpc() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        if (hasView()) {
            extensionHook.getHookMenu().addToolsMenuItem(getProtoBufToolsMenuItem());
        }
    }

    private ZapMenuItem getProtoBufToolsMenuItem() {
        if (protoBufToolsMenuItem == null) {
            protoBufToolsMenuItem = new ZapMenuItem("grpc.tools.menu.encdec");
            protoBufToolsMenuItem.setToolTipText(
                    Constant.messages.getString("grpc.tools.menu.encdec.tooltip"));
            protoBufToolsMenuItem.addActionListener(e -> getProtoBufEditorDialog());
        }
        return protoBufToolsMenuItem;
    }

    private void getProtoBufEditorDialog() {
        if (protoBufEditorDialog == null) {
            protoBufEditorDialog =
                    new ProtoBufEditorDialog(View.getSingleton().getMainFrame(), true);
        }
        protoBufEditorDialog.setVisible(true);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("grpc.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("grpc.desc");
    }
}
