/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2010 The ZAP Development Team
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
package org.zaproxy.zap.extension.invoke;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionHookView;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.parosproxy.paros.view.View;

public class ExtensionInvoke extends ExtensionAdaptor {

    private PopupMenuInvokers popupMenuInvokers;

    private OptionsInvokePanel optionsInvokePanel;

    private InvokeParam invokeParam;

    /** */
    public ExtensionInvoke() {
        super("ExtensionInvoke");
        this.setOrder(46);
    }

    @Override
    public void init() {
        super.init();
        invokeParam = new InvokeParam();
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addOptionsParamSet(invokeParam);

        if (getView() != null) {
            popupMenuInvokers = new PopupMenuInvokers();

            @SuppressWarnings("unused")
            ExtensionHookView pv = extensionHook.getHookView();
            extensionHook.getHookView().addOptionPanel(getOptionsInvokePanel());

            extensionHook.getHookMenu().addPopupMenuItem(popupMenuInvokers);
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void optionsLoaded() {
        if (View.isInitialised()) {
            List<InvokableApp> apps = invokeParam.getListInvokeEnabled();
            popupMenuInvokers.setApps(apps);
        }
    }

    private AbstractParamPanel getOptionsInvokePanel() {
        if (optionsInvokePanel == null) {
            optionsInvokePanel = new OptionsInvokePanel(this);
        }
        return optionsInvokePanel;
    }

    protected void replaceInvokeMenus(List<InvokableApp> apps) {
        popupMenuInvokers.setApps(apps);
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("invoke.desc");
    }
}
