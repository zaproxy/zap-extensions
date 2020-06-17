/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.cmss;

import java.util.ResourceBundle;
import javax.swing.JMenuItem;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

/*
 * An example ZAP extension which adds a top level menu item.
 *
 * This class defines the extension.
 */
public class CMSSTopMenu extends ExtensionAdaptor {

    private JMenuItem menuExample = null;
    private ResourceBundle messages = null;

    /** */
    public CMSSTopMenu() {
        super("ExtensionTopMenu");
        // Load extension specific language files - these are held in the extension jar
        messages =
                ResourceBundle.getBundle(
                        this.getClass().getPackage().getName() + ".resources.Messages",
                        Constant.getLocale());
    }

    @SuppressWarnings("deprecation")
    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            // Register our top menu item, as long as we're not running as a daemon
            // Use one of the other methods to add to a different menu list

            extensionHook.getHookMenu().addToolsMenuItem(getMenuExample());
        }
    }

    private JMenuItem getMenuExample() {

        menuExample = new JMenuItem();
        menuExample.setName("Fingerprinting tools");
        menuExample.setText("Fingerprinting tools");

        menuExample.addActionListener(
                new java.awt.event.ActionListener() {
                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent e) {
                        // This is where you do what you want to do.
                        // In this case we'll just show a popup message.
                        CMSSThread cmssThread = new CMSSThread();
                        cmssThread.start();
                    }
                });

        return menuExample;
    }

    public String getMessageString(String key) {
        return messages.getString(key);
    }

    @Override
    public String getDescription() {
        return messages.getString("ext.topmenu.desc");
    }
}
