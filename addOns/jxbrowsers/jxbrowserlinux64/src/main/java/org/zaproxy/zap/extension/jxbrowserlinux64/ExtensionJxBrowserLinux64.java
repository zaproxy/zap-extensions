/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2017 The ZAP Development Team
 *  
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.jxbrowserlinux64;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.SwingUtilities;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.jxbrowser.ExtensionJxBrowser;
import org.zaproxy.zap.extension.jxbrowser.Utils;
import org.zaproxy.zap.extension.jxbrowser.ZapBrowserFrame;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionJxBrowserLinux64 extends ExtensionAdaptor {

    public static final String NAME = "ExtensionJxBrowserLinux64";

    private static final Logger LOGGER = Logger.getLogger(ExtensionJxBrowserLinux64.class);

    private static final ImageIcon CHROMIUM_ICON = DisplayUtils.getScaledIcon(
            new ImageIcon(ExtensionJxBrowser.class.getResource(ExtensionJxBrowser.RESOURCES + "/chromium.png")));

    private JButton launchBrowserButton;

    public ExtensionJxBrowserLinux64() {
        super(NAME);
    }

    @Override
    public void init() {
        super.init();
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {

            if (Constant.isLinux() && Utils.isOs64Bits()) {
                // Only show if we're running on the right platform
                View.getSingleton().addMainToolbarButton(this.getLaunchBrowserButton());
    
                ZapMenuItem menulaunch = new ZapMenuItem("jxbrowser.menu.launch");
                menulaunch.addActionListener(new java.awt.event.ActionListener() {
    
                    @Override
                    public void actionPerformed(java.awt.event.ActionEvent ae) {
                        launchBrowser(null);
                    }
                });
    
                extensionHook.getHookMenu().addToolsMenuItem(menulaunch);
            }
        }
    }
    
    private JButton getLaunchBrowserButton() {
        if (launchBrowserButton == null) {
            launchBrowserButton = new JButton();
            launchBrowserButton.setIcon(CHROMIUM_ICON);
            launchBrowserButton.setToolTipText(Constant.messages.getString("jxbrowser.button.launch"));
            launchBrowserButton.addActionListener(new ActionListener() {

                @Override
                public void actionPerformed(ActionEvent e) {
                    launchBrowser(null);
                }
            });
        }
        return launchBrowserButton;
    }

    private void launchBrowser(final String url) {
        SwingUtilities.invokeLater(new Runnable() {

            @Override
            public void run() {
                try {
                    ZapBrowserFrame zbf = new ZapBrowserFrame(true, true);
                    if (url != null) {
                        zbf.getBrowser().loadURL(url);
                    }
                } catch (Exception e) {
                    LOGGER.error(e.getMessage(), e);
                }
            }
        });

    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        super.unload();
        if (launchBrowserButton != null) {
            View.getSingleton().removeMainToolbarButton(launchBrowserButton);
        }
    }

    @Override
    public String getAuthor() {
        return Constant.ZAP_TEAM;
    }
}
