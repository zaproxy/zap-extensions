/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.regextester;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.regextester.ui.RegexDialog;
import org.zaproxy.zap.extension.regextester.ui.model.RegexModel;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionRegExTester extends ExtensionAdaptor {
    public static final String NAME = "ExtensionRegExTester";
    public static final int EXTENSION_ORDER = 85;

    private ZapMenuItem menuItemRegExTester = null;
    private List<WeakReference<RegexDialog>> dialogs;

    public ExtensionRegExTester() {
        super(NAME);
        this.setOrder(EXTENSION_ORDER);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        if (getView() != null) {
            dialogs = new ArrayList<>();
            extensionHook.getHookMenu().addToolsMenuItem(getMenuItemRegExTester());
            extensionHook.getHookMenu().addPopupMenuItem(new RegExTesterPopupMenuItem(this));
        }
    }

    private ZapMenuItem getMenuItemRegExTester() {
        if (menuItemRegExTester == null) {
            menuItemRegExTester = new ZapMenuItem("regextester.menu.tools.name");
            menuItemRegExTester.addActionListener(e -> showDialog());
        }
        return menuItemRegExTester;
    }

    public RegexDialog showDialog() {
        return showDialog("", "");
    }

    public RegexDialog showDialog(String regex, String text) {
        RegexDialog dialog = new RegexDialog(new RegexModel(regex, text));
        dialogs.add(new WeakReference<>(dialog));
        dialog.setVisible(true);
        return dialog;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        if (dialogs != null) {
            dialogs.forEach(
                    e -> {
                        RegexDialog dialog = e.get();
                        if (dialog != null) {
                            dialog.dispose();
                            e.clear();
                        }
                    });
        }
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("regextester.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("regextester.desc");
    }
}
