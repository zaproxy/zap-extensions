/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.quickstart;

import javax.swing.JComboBox;
import javax.swing.JComponent;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.extension.selenium.ProvidedBrowserUI;
import org.zaproxy.zap.extension.selenium.ProvidedBrowsersComboBoxModel;

public class SeleniumBrowserSelector implements BrowserSelector {

    private final JComboBox<ProvidedBrowserUI> combo;

    public SeleniumBrowserSelector() {
        combo = new JComboBox<>();
        ExtensionSelenium extSelenium =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
        if (extSelenium != null) {
            ProvidedBrowsersComboBoxModel model = extSelenium.createProvidedBrowsersComboBoxModel();
            model.setIncludeUnconfigured(false);
            model.setSelectedBrowser(Browser.FIREFOX_HEADLESS.getId());
            combo.setModel(model);
        }
    }

    @Override
    public JComponent getComponent() {
        return combo;
    }

    @Override
    public String getSelectedBrowserId() {
        ProvidedBrowserUI item = (ProvidedBrowserUI) combo.getSelectedItem();
        return item != null ? item.getBrowser().getId() : null;
    }

    @Override
    public String getSelectedBrowserName() {
        Object item = combo.getSelectedItem();
        return item != null ? item.toString() : null;
    }

    @Override
    public void restoreSelection(String savedBrowserName) {
        if (savedBrowserName == null || savedBrowserName.isEmpty()) {
            return;
        }
        for (int i = 0; i < combo.getModel().getSize(); i++) {
            ProvidedBrowserUI el = combo.getModel().getElementAt(i);
            if (el.getName().equals(savedBrowserName)) {
                combo.setSelectedItem(el);
                break;
            }
        }
    }
}
