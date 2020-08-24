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
package org.zaproxy.zap.extension.gettingStarted;

import java.awt.Desktop;
import java.io.File;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.view.ZapMenuItem;

/** A short Getting Started with ZAP Guide. */
public class ExtensionGettingStarted extends ExtensionAdaptor {

    private static Logger logger = Logger.getLogger(ExtensionGettingStarted.class);

    private static final String DIR = "lang";

    private ZapMenuItem menuGettingStarted = null;

    public ExtensionGettingStarted() {
        super("ExtensionGettingStarted");
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        if (getView() != null) {
            /* Register our top menu item, as long as we're not running as a daemon
             * Use one of the other methods to add to a different menu list
             */
            extensionHook.getHookMenu().addHelpMenuItem(getMenuGettingStarted());
        }
    }

    private ZapMenuItem getMenuGettingStarted() {
        if (menuGettingStarted == null) {
            menuGettingStarted = new ZapMenuItem("gettingStarted.menu");
            menuGettingStarted.addActionListener(
                    new java.awt.event.ActionListener() {
                        @Override
                        public void actionPerformed(java.awt.event.ActionEvent event) {
                            try {
                                /* Note that if you translate the guide to another language you need to also change
                                 * the language file so that gettingStarted.file refers to the localized file name
                                 */
                                File guide =
                                        new File(
                                                Constant.getZapHome()
                                                        + File.separator
                                                        + DIR
                                                        + File.separator
                                                        + Constant.messages.getString(
                                                                "gettingStarted.file"));
                                logger.debug("Getting started guide: " + guide.getAbsolutePath());
                                Desktop.getDesktop().open(guide);
                            } catch (Exception ex) {
                                logger.error(
                                        "Failed to locate or open Getting started guide: ", ex);
                            }
                        }
                    });
        }
        return menuGettingStarted;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("gettingStarted.desc");
    }
}
