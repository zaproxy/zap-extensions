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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.jxbrowser;

import java.awt.BorderLayout;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JToolBar;

import org.zaproxy.zap.view.LayoutHelper;

import com.teamdev.jxbrowser.chromium.Browser;
import com.teamdev.jxbrowser.chromium.ContextMenuHandler;
import com.teamdev.jxbrowser.chromium.events.FailLoadingEvent;
import com.teamdev.jxbrowser.chromium.events.FinishLoadingEvent;
import com.teamdev.jxbrowser.chromium.events.FrameLoadEvent;
import com.teamdev.jxbrowser.chromium.events.LoadEvent;
import com.teamdev.jxbrowser.chromium.events.LoadListener;
import com.teamdev.jxbrowser.chromium.events.ProvisionalLoadingEvent;
import com.teamdev.jxbrowser.chromium.events.StartLoadingEvent;
import com.teamdev.jxbrowser.chromium.swing.BrowserView;

/**
 * A JxBrowser panel. It is not i18n so should only be used for testing.
 * @author psiinon
 *
 */
public class BrowserPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private BrowserFrame frame;
    protected Browser browser;
    private JTextField url;
    protected JButton backButton;
    protected JButton forwardButton;
    protected JButton helpButton;

    public BrowserPanel(BrowserFrame frame) {
        this(frame, true);
    }

    public BrowserPanel(BrowserFrame frame, boolean incToolbar) {
        this(frame, incToolbar, null);
    }

    public BrowserPanel(BrowserFrame frame, boolean incToolbar, Browser browser) {
        this.frame = frame;
        
        if (browser == null) {
            // Set up the browser
            getBrowser();
        } else {
            this.browser = browser;
        }
        JToolBar toolbar = null;

        if (incToolbar) {
            // Set up the toolbar
            toolbar = new JToolBar();
            toolbar.setLayout(new GridBagLayout());
            url = new JTextField("", 30);
            toolbar.setRollover(true);
            toolbar.setFloatable(false);
            getBackButton().addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    BrowserPanel.this.browser.goBack();
                    url.setText(BrowserPanel.this.browser.getURL());
                }
            });
            getForwardButton().addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    BrowserPanel.this.browser.goForward();
                    url.setText(BrowserPanel.this.browser.getURL());
                }
            });

            int x = 0;
            toolbar.add(getBackButton(), LayoutHelper.getGBC(x++, 0, 1, 0.0));
            toolbar.add(getForwardButton(), LayoutHelper.getGBC(x++, 0, 1, 0.0));
            for (JButton button : this.getExtraButtons()) {
                toolbar.add(button, LayoutHelper.getGBC(x++, 0, 1, 0.0));
            }
            toolbar.add(url, LayoutHelper.getGBC(x++, 0, 1, 1.0));
            toolbar.add(getHelpButton(), LayoutHelper.getGBC(x++, 0, 1, 0.0));

            // Set up the listeners
            url.addActionListener(new ActionListener() {

                @Override
                public void actionPerformed(ActionEvent e) {
                    BrowserPanel.this.browser.loadURL(url.getText());
                }
            });

            this.browser.addLoadListener(new LoadListener() {

                @Override
                public void onDocumentLoadedInFrame(FrameLoadEvent arg0) {
                }

                @Override
                public void onDocumentLoadedInMainFrame(LoadEvent arg0) {
                    url.setText(BrowserPanel.this.browser.getURL());
                }

                @Override
                public void onFailLoadingFrame(FailLoadingEvent arg0) {
                }

                @Override
                public void onFinishLoadingFrame(FinishLoadingEvent arg0) {
                }

                @Override
                public void onProvisionalLoadingFrame(ProvisionalLoadingEvent arg0) {
                }

                @Override
                public void onStartLoadingFrame(StartLoadingEvent arg0) {
                }
            });
        }

        // Build up the browser panel
        this.setLayout(new BorderLayout());
        if (incToolbar) {
            this.add(toolbar, BorderLayout.NORTH);
        }
        BrowserView browserView = new BrowserView(this.browser);
        // Disabled for now - too many issues with it
        //getBrowser().setContextMenuHandler(getContextMenuHandler(browserView));
        this.add(browserView, BorderLayout.CENTER);
        
    }
    
    public Browser getBrowser() {
        if (browser == null) {
            /* Test code for proxying through ZAP
            try {
                File dataFile = Files.createTempDirectory("zap-jxbrowser").toFile();
                dataFile.deleteOnExit();
                BrowserContextParams contextParams = new BrowserContextParams(dataFile.getAbsolutePath());
                String hostPort = "localhost:8090";
                String proxyRules = "http=" + hostPort + ";https=" + hostPort;
                contextParams.setProxyConfig(new CustomProxyConfig(proxyRules));
                browser = new Browser(new BrowserContext(contextParams));
            } catch (IOException e) {
                browser = new Browser();
            }
            */
            browser = new Browser();
        }
        return browser;
    }
    
    protected ContextMenuHandler getContextMenuHandler(BrowserView browserView) {
        return new BrowserContextMenuHandler(frame, browserView);
    }
    
    protected void selectToolbarUrl() {
        if (url != null) {
            url.grabFocus();
        }
    }

    protected void close() {
        browser.dispose();
    }
    
    protected JButton getBackButton() {
        if (backButton == null) {
            backButton = new JButton("<");
            backButton.setToolTipText("Go backwards one page");
        }
        return backButton;
    }

    protected JButton getForwardButton() {
        if (forwardButton == null) {
            forwardButton = new JButton(">");
            forwardButton.setToolTipText("Go forwards one page");
        }
        return forwardButton;
    }

    protected JButton[] getExtraButtons() {
        return new JButton[]{};
    }

    protected JButton getHelpButton() {
        if (helpButton == null) {
            helpButton = new JButton("?");
            helpButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    JOptionPane.showMessageDialog(BrowserPanel.this, "Help text to go here");
                }
            });
        }
        return helpButton;
    }

}
