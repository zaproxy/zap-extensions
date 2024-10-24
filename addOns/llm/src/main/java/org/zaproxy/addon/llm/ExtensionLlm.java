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
package org.zaproxy.addon.llm;

import java.awt.CardLayout;
import java.awt.Font;
import java.awt.event.KeyEvent;
import java.io.File;
import java.nio.file.Files;
import javax.swing.ImageIcon;
import javax.swing.JTextPane;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.ZapMenuItem;

/**
 * An example ZAP extension which adds a top level menu item, a pop up menu item and a status panel.
 *
 * <p>{@link ExtensionAdaptor} classes are the main entry point for adding/loading functionalities
 * provided by the add-ons.
 *
 * @see #hook(ExtensionHook)
 */
public class ExtensionLlm extends ExtensionAdaptor {

    // The name is public so that other extensions can access it
    public static final String NAME = "ExtensionLlm";

    // The i18n prefix, by default the package name - defined in one place to make it easier
    // to copy and change this example
    protected static final String PREFIX = "llm";

    /**
     * Relative path (from add-on package) to load add-on resources.
     *
     * @see Class#getResource(String)
     */
    private static final String RESOURCES = "resources";

    private ZapMenuItem menuExample;
    private AbstractPanel statusPanel;
    private ImportDialog importDialog;
    private CheckLlmMenu checkLlmMenu;
    private LlmOptionsParam llmOptionsParam;
    private LlmOptionsPanel llmOptionsPanel;
    private static final String[] ROOT = {};

    private LlmAPI api;

    private static final Logger LOGGER = LogManager.getLogger(ExtensionLlm.class);

    public ExtensionLlm() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        this.llmOptionsParam = new LlmOptionsParam();


        if (hasView()) {
            extensionHook.getHookMenu().addImportMenuItem(getMenuLLM());
            extensionHook.getHookMenu().addPopupMenuItem(getCheckLlmMenu());
            extensionHook.addOptionsParamSet(getOptionsParam());
            // change to a message
            getView().getOptionsDialog().addParamPanel(ROOT, getOptionsPanel(), true);

            extensionHook.addSessionListener(
                    new SessionChangedListener() {
                        @Override
                        public void sessionAboutToChange(Session session) {
                            if (importDialog != null) {
                                importDialog.clearFields();
                            }
                        }

                        @Override
                        public void sessionChanged(Session session) {}

                        @Override
                        public void sessionScopeChanged(Session session) {}

                        @Override
                        public void sessionModeChanged(Control.Mode mode) {}
                    });
        }
    }

    @Override
    public boolean canUnload() {
        // The extension can be dynamically unloaded, all resources used/added can be freed/removed
        // from core.
        return true;
    }

    @Override
    public void unload() {
        super.unload();

        // In this example it's not necessary to override the method, as there's nothing to unload
        // manually, the components added through the class ExtensionHook (in hook(ExtensionHook))
        // are automatically removed by the base unload() method.
        // If you use/add other components through other methods you might need to free/remove them
        // here (if the extension declares that can be unloaded, see above method).
        if (importDialog != null) {
            importDialog.dispose();
        }
    }

    private AbstractPanel getStatusPanel() {
        if (statusPanel == null) {
            statusPanel = new AbstractPanel();
            statusPanel.setLayout(new CardLayout());
            statusPanel.setName(Constant.messages.getString(PREFIX + ".panel.title"));
            statusPanel.setIcon(new ImageIcon(getClass().getResource(RESOURCES + "/cake.png")));
            JTextPane pane = new JTextPane();
            pane.setEditable(false);
            // Obtain (and set) a font with the size defined in the options
            pane.setFont(FontUtils.getFont("Dialog", Font.PLAIN));
            pane.setContentType("text/html");
            pane.setText(Constant.messages.getString(PREFIX + ".panel.msg"));
            statusPanel.add(pane);
        }
        return statusPanel;
    }

    private ZapMenuItem getMenuLLM() {
        if (menuExample == null) {
            menuExample =
                    new ZapMenuItem(
                            "llm.topmenu.import.importSwagger",
                            getView().getMenuShortcutKeyStroke(KeyEvent.VK_J, 0, false));
            menuExample.setToolTipText(
                    Constant.messages.getString("llm.topmenu.import.importSwagger.tooltip"));
            menuExample.addActionListener(
                    e -> {
                        if (importDialog == null) {
                            importDialog = new ImportDialog(getView().getMainFrame(), this);
                        }
                        importDialog.setVisible(true);
                    });
        }
        return menuExample;
    }
    private void displayFile(String file) {
        if (!View.isInitialised()) {
            // Running in daemon mode, shouldnt have been called
            return;
        }
        try {
            File f = new File(Constant.getZapHome(), file);
            if (!f.exists()) {
                // This is something the user should know, so show a warning dialog
                View.getSingleton()
                        .showWarningDialog(
                                Constant.messages.getString(
                                        ExtensionLlm.PREFIX + ".error.nofile",
                                        f.getAbsolutePath()));
                return;
            }
            // Quick way to read a small text file
            String contents = new String(Files.readAllBytes(f.toPath()));
            // Write to the output panel
            View.getSingleton().getOutputPanel().append(contents);
            // Give focus to the Output tab
            View.getSingleton().getOutputPanel().setTabFocus();
        } catch (Exception e) {
            // Something unexpected went wrong, write the error to the log
            LOGGER.error(e.getMessage(), e);
        }
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".desc");
    }

    private CheckLlmMenu getCheckLlmMenu() {
        if (checkLlmMenu == null) {
            checkLlmMenu = new CheckLlmMenu(this);
        }
        return checkLlmMenu;
    }

    private LlmOptionsPanel getOptionsPanel() {
        if (llmOptionsPanel == null) {
            llmOptionsPanel = new LlmOptionsPanel();
        }
        return llmOptionsPanel;
    }

    public LlmOptionsParam getOptionsParam() {
        if (llmOptionsParam == null) {
            llmOptionsParam = new LlmOptionsParam();
        }
        return llmOptionsParam;
    }

}
