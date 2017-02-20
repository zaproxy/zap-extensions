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
package org.zaproxy.zap.extension.jxbrowser;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import javax.swing.ImageIcon;
import javax.swing.JButton;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.utils.DisplayUtils;

import com.teamdev.jxbrowser.chromium.Browser;
import com.teamdev.jxbrowser.chromium.BrowserContext;
import com.teamdev.jxbrowser.chromium.BrowserContextParams;
import com.teamdev.jxbrowser.chromium.CustomProxyConfig;

public class ZapBrowserPanel extends BrowserPanel {

    private static final ImageIcon BACK_ICON = DisplayUtils.getScaledIcon(new ImageIcon(
            ZapBrowserPanel.class.getResource(ExtensionJxBrowser.RESOURCES + "/arrow-180-medium.png")));

    private static final ImageIcon FORWARD_ICON = DisplayUtils.getScaledIcon(new ImageIcon(
            ZapBrowserPanel.class.getResource(ExtensionJxBrowser.RESOURCES + "/arrow-000-medium.png")));

    private static final Logger LOGGER = Logger.getLogger(ZapBrowserPanel.class);
    private static final long serialVersionUID = 1L;

    public ZapBrowserPanel(BrowserFrame frame, boolean incToolbar) {
        super(frame, incToolbar);
    }

    @Override
    public Browser getBrowser() {
        if (browser == null) {
            try {
                // Always proxy through ZAP
                File dataFile = Files.createTempDirectory("zap-jxbrowser").toFile();
                dataFile.deleteOnExit();
                BrowserContextParams contextParams = new BrowserContextParams(dataFile.getAbsolutePath());
                String hostPort = Model.getSingleton().getOptionsParam().getProxyParam().getProxyIp() + ":"
                        + Model.getSingleton().getOptionsParam().getProxyParam().getProxyPort();
                String proxyRules = "http=" + hostPort + ";https=" + hostPort;
                contextParams.setProxyConfig(new CustomProxyConfig(proxyRules));
                browser = new Browser(new BrowserContext(contextParams));
            } catch (IOException e) {
                LOGGER.error(e.getMessage(), e);
                browser = new Browser();
            }
        }
        return browser;
    }

    @Override
    protected JButton getBackButton() {
        if (backButton == null) {
            backButton = new JButton();
            backButton.setIcon(BACK_ICON);
            backButton.setToolTipText(Constant.messages.getString("jxbrowser.browser.button.back"));
        }
        return backButton;
    }

    @Override
    protected JButton getForwardButton() {
        if (forwardButton == null) {
            forwardButton = new JButton();
            forwardButton.setIcon(FORWARD_ICON);
            forwardButton.setToolTipText(Constant.messages.getString("jxbrowser.browser.button.fwds"));
        }
        return forwardButton;
    }

    @Override
    protected JButton getHelpButton() {
        if (helpButton == null) {
            helpButton = new JButton();
            helpButton.setIcon(ExtensionHelp.HELP_ICON);
            helpButton.setToolTipText(Constant.messages.getString("jxbrowser.browser.button.help"));
            helpButton.addActionListener(new ActionListener() {

                @Override
                public void actionPerformed(ActionEvent e) {
                    ExtensionHelp.showHelp("jxbrowser");
                }
            });
        }
        return helpButton;
    }

}
