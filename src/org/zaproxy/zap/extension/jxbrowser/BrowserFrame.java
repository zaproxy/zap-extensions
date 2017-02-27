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

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.WindowConstants;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.parosproxy.paros.view.AbstractFrame;

import com.teamdev.jxbrowser.chromium.Browser;
import com.teamdev.jxbrowser.chromium.events.TitleEvent;
import com.teamdev.jxbrowser.chromium.events.TitleListener;

/**
 * A tabbed JxBrowser frame. It is not i18n but can be run from the commandline for testing purposes.
 * @author psiinon
 *
 */
public class BrowserFrame extends AbstractFrame {

    private static final long serialVersionUID = 1L;

    private List<BrowserPanel> zapPanels = new ArrayList<BrowserPanel>();
    protected JTabbedPane tabbedPane;

    private final boolean incToolbar; 
    private int prevTabIndex;
    private boolean inTab;

    public BrowserFrame() {
        this(true, true);
    }

    public BrowserFrame(final boolean incToolbar, final boolean supportTabs) {
        this(incToolbar, supportTabs, true);
    }

    public BrowserFrame(final boolean incToolbar, final boolean supportTabs, boolean createBrowser) {
        this(incToolbar, supportTabs, createBrowser, true);
    }

    public BrowserFrame(final boolean incToolbar, final boolean supportTabs, boolean createBrowser, boolean showNewTab) {
        this.incToolbar = incToolbar;
        this.setWindowTitle(null);
        this.setLayout(new BorderLayout());

        if (supportTabs) {
            // Initialise tabbedPane before loading the panel
            getTabbedPane();
        }

        BrowserPanel zbp = null;
        if (createBrowser) {
            zbp = addNewBrowserPanel();
            zbp.getBrowser().loadHTML(getFirstPageHtml());
        }

        if (supportTabs) {
            // Initialise
            if (showNewTab) {
                this.addPlusTab();
            }

            this.add(tabbedPane, BorderLayout.CENTER);


            if (showNewTab) {
                // Handle the + tab being clicked
                tabbedPane.addChangeListener(new ChangeListener() {
    
                    private boolean addingTab = false;
    
                    @Override
                    public void stateChanged(ChangeEvent e) {
                        if (!addingTab && tabbedPane.getSelectedIndex() == tabbedPane.getTabCount() - 1) {
                            if (!inTab) {
                                // The mouse isnt in the tab, so assume the user is using the keyboard to switch tabs
                                // in which case we dont want to create a new one
                                if (prevTabIndex == 0) {
                                    // Select 2nd from right, ie not the + tab
                                    tabbedPane.setSelectedIndex(tabbedPane.getTabCount() - 2);
                                } else {
                                    // Select first
                                    tabbedPane.setSelectedIndex(0);
                                }
                                prevTabIndex = tabbedPane.getSelectedIndex();
                                return;
                            }
    
                            addingTab = true;
                            BrowserPanel zbp2 = addNewBrowserPanel();
                            tabbedPane.setSelectedIndex(tabbedPane.getTabCount() - 2); // There will be another tab now ;)
                            titleChanged(zbp2);
                            zbp2.selectToolbarUrl();
                            addingTab = false;
                        } else {
                            Component c = tabbedPane.getSelectedComponent();
                            if (c instanceof BrowserPanel) {
                                titleChanged((BrowserPanel) tabbedPane.getSelectedComponent());
                            }
    
                        }
                        prevTabIndex = tabbedPane.getSelectedIndex();
                    }
                });
            }
            tabbedPane.addMouseListener(new MouseAdapter() {

                @Override
                public void mouseEntered(MouseEvent e) {
                    inTab = true;
                }

                @Override
                public void mouseExited(MouseEvent e) {
                    inTab = false;
                }
            });

        } else if (createBrowser) {
            this.add(zbp, BorderLayout.CENTER);
        }
        
        this.addWindowListener(new WindowAdapter() {

            @Override
            public void windowClosing(java.awt.event.WindowEvent windowEvent) {
                close();
            }

        });

        this.setVisible(true);

    }
    
    protected String getFirstPageHtml() {
        return "<html><head><title>Welcome</title></head><body>" +
                "<h3>Welcome to the ZAP Browser (based on JxBrowser)</h3>" +
                "<p>This is the test version which runs from the command line.</p>" +
                "</body><html>";
    }

    protected String getNewTabTitle() {
        return "New Tab";
    }

    protected void addPlusTab() {
        tabbedPane.addTab("+", new JPanel());
    }

    protected void insertTab(Component component, int index) {
        tabbedPane.insertTab(getNewTabTitle(), null, component, null, index);

    }

    public void removeTab(Component component) {
        zapPanels.remove(component);
        getTabbedPane().remove(component);
    }

    protected BrowserPanel getNewBrowserPanel(boolean incToolbar) {
        return new BrowserPanel(this, incToolbar);
    }

    protected BrowserPanel getNewBrowserPanel(boolean incToolbar, Browser browser) {
        return new BrowserPanel(this, incToolbar, browser);
    }

    public BrowserPanel addNewBrowserPanel(String url) {
        BrowserPanel panel = addNewBrowserPanel();
        panel.getBrowser().loadURL(url);
        // Always switch to the new tab (at least for now)
        System.out.println("Tab count " + tabbedPane.getTabCount());
        tabbedPane.setSelectedIndex(tabbedPane.getTabCount() - 2);
        
        return panel;
    }

    public BrowserPanel addNewBrowserPanel() {
        final BrowserPanel zbp = getNewBrowserPanel(incToolbar);
        zapPanels.add(zbp);
        insertTab(zbp, tabbedPane.getTabCount() > 0 ? tabbedPane.getTabCount() - 1 : 0);
        zbp.getBrowser().addTitleListener(new TitleListener() {

            @Override
            public void onTitleChange(TitleEvent arg0) {
                titleChanged(zbp);
            }

        });

        return zbp;
    }

    public BrowserPanel addNewBrowserPanel(boolean incToolbar, Browser browser) {
        final BrowserPanel zbp = getNewBrowserPanel(incToolbar, browser);
        zapPanels.add(zbp);
        insertTab(zbp, tabbedPane.getTabCount() > 0 ? tabbedPane.getTabCount() - 1 : 0);
        zbp.getBrowser().addTitleListener(new TitleListener() {

            @Override
            public void onTitleChange(TitleEvent arg0) {
                titleChanged(zbp);
            }

        });

        return zbp;
    }

    protected void setWindowTitle(String title) {
        if (title == null) {
            this.setTitle("ZAP Browser (JxBrowser)");
        } else {
            this.setTitle(title + " - ZAP Browser (JxBrowser)");
        }
    }

    protected void titleChanged(BrowserPanel bp) {
        int index = tabbedPane.indexOfComponent(bp);

        if (index == tabbedPane.getSelectedIndex()) {
            String title = bp.getBrowser().getTitle();
            if (title.equals("about:blank")) {
                title = this.getNewTabTitle();
            }
            this.setWindowTitle(title);
            if (title.length() > 20) {
                title = title.substring(0, 20) + "...";
            }
            tabbedPane.setTitleAt(index, title);
        }

    }

    public void close() {
        for (BrowserPanel zp : zapPanels) {
            zp.close();
        }
    }

    public Browser getBrowser() {
        return this.zapPanels.get(0).getBrowser();
    }

    protected JTabbedPane getTabbedPane() {
        if (tabbedPane == null) {
            tabbedPane = new JTabbedPane();
        }
        return tabbedPane;
    }

    public boolean hasPanels() {
        return !zapPanels.isEmpty();
    }

    public static void main(String[] args) {
        BrowserFrame zbf = new BrowserFrame(true, true);
        zbf.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
    }
}
