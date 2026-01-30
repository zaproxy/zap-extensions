/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.selenium;

import java.awt.BorderLayout;
import java.awt.Dialog;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.BorderFactory;
import javax.swing.GroupLayout;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.TitledBorder;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.selenium.BrowserExtension.BrowserExtensionFileFilter;
import org.zaproxy.zap.extension.selenium.internal.BrowserArgumentsTableModel;
import org.zaproxy.zap.extension.selenium.internal.CustomBrowserImpl;
import org.zaproxy.zap.extension.selenium.internal.CustomBrowsersTableModel;
import org.zaproxy.zap.extension.selenium.internal.DialogCustomBrowser;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.view.AbstractMultipleOptionsBaseTableModel;
import org.zaproxy.zap.view.AbstractMultipleOptionsBaseTablePanel;
import org.zaproxy.zap.view.AbstractMultipleOptionsTableModel;

/**
 * The GUI Selenium options panel.
 *
 * <p>It allows to change the following options:
 *
 * <ul>
 *   <li>The path to ChromeDriver;
 *   <li>The path to Firefox binary.
 *   <li>The path to Firefox driver (geckodriver).
 *   <li>The path to PhantomJS binary.
 * </ul>
 *
 * @see SeleniumOptions
 */
@SuppressWarnings("serial")
class SeleniumOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = -4918932139321106800L;

    private final BrowserArgumentsTableModel chromeArgumentsTableModel;
    private final BrowserArgumentsTableModel edgeArgumentsTableModel;
    private final BrowserArgumentsTableModel firefoxArgumentsTableModel;
    private final OptionsBrowserExtensionsTableModel browserExtModel;
    private final CustomBrowsersTableModel customBrowsersModel;
    private final AtomicBoolean confirmRemoveBrowserArgument;
    private final ExtensionSelenium extSelenium;
    private static String directory;

    private static String getBuiltInBrowserName(Browser browser) {
        // Use the same i18n'd names as the rest of the Selenium extension.
        return ExtensionSelenium.getName(browser);
    }

    public SeleniumOptionsPanel(
            ExtensionSelenium extSelenium, Dialog parent, ResourceBundle resourceBundle) {
        this.extSelenium = extSelenium;
        setName(resourceBundle.getString("selenium.options.title"));

        confirmRemoveBrowserArgument = new AtomicBoolean();
        chromeArgumentsTableModel = new BrowserArgumentsTableModel();
        edgeArgumentsTableModel = new BrowserArgumentsTableModel();
        firefoxArgumentsTableModel = new BrowserArgumentsTableModel();

        JPanel browserExtPanel = new JPanel();
        GroupLayout browserExtLayout = new GroupLayout(browserExtPanel);
        browserExtPanel.setLayout(browserExtLayout);

        browserExtLayout.setAutoCreateGaps(true);
        browserExtLayout.setAutoCreateContainerGaps(true);

        browserExtModel = new OptionsBrowserExtensionsTableModel();

        browserExtPanel.setBorder(
                BorderFactory.createTitledBorder(
                        null,
                        resourceBundle.getString("selenium.options.extensions.title"),
                        TitledBorder.DEFAULT_JUSTIFICATION,
                        TitledBorder.DEFAULT_POSITION,
                        FontUtils.getFont(FontUtils.Size.standard)));

        BrowserExtMultipleOptionsPanel browserExtOptionsPanel =
                new BrowserExtMultipleOptionsPanel(this.browserExtModel, resourceBundle);

        browserExtLayout.setHorizontalGroup(
                browserExtLayout.createSequentialGroup().addComponent(browserExtOptionsPanel));
        browserExtLayout.setVerticalGroup(
                browserExtLayout.createSequentialGroup().addComponent(browserExtOptionsPanel));

        JPanel customBrowsersPanel = new JPanel();
        GroupLayout customBrowsersLayout = new GroupLayout(customBrowsersPanel);
        customBrowsersPanel.setLayout(customBrowsersLayout);

        customBrowsersLayout.setAutoCreateGaps(true);
        customBrowsersLayout.setAutoCreateContainerGaps(true);

        customBrowsersModel = new CustomBrowsersTableModel();

        customBrowsersPanel.setBorder(
                BorderFactory.createTitledBorder(
                        null,
                        resourceBundle.getString("selenium.options.custom.browsers.title"),
                        TitledBorder.DEFAULT_JUSTIFICATION,
                        TitledBorder.DEFAULT_POSITION,
                        FontUtils.getFont(FontUtils.Size.standard)));

        CustomBrowsersMultipleOptionsPanel customBrowsersOptionsPanel =
                new CustomBrowsersMultipleOptionsPanel(
                        this.customBrowsersModel, resourceBundle, parent);

        customBrowsersLayout.setHorizontalGroup(
                customBrowsersLayout
                        .createSequentialGroup()
                        .addComponent(customBrowsersOptionsPanel));
        customBrowsersLayout.setVerticalGroup(
                customBrowsersLayout
                        .createSequentialGroup()
                        .addComponent(customBrowsersOptionsPanel));

        JPanel innerPanel = new JPanel();
        GroupLayout layout = new GroupLayout(innerPanel);
        innerPanel.setLayout(layout);

        layout.setAutoCreateGaps(true);
        layout.setAutoCreateContainerGaps(true);

        layout.setHorizontalGroup(
                layout.createParallelGroup()
                        .addComponent(customBrowsersPanel)
                        .addComponent(browserExtPanel));
        layout.setVerticalGroup(
                layout.createSequentialGroup()
                        .addComponent(customBrowsersPanel)
                        .addComponent(browserExtPanel));

        setLayout(new BorderLayout());
        add(
                new JScrollPane(
                        innerPanel,
                        ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                        ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER));
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam optionsParam = (OptionsParam) obj;
        SeleniumOptions seleniumOptions = optionsParam.getParamSet(SeleniumOptions.class);

        confirmRemoveBrowserArgument.set(seleniumOptions.isConfirmRemoveBrowserArgument());

        // Create built-in browsers
        List<CustomBrowserImpl> allBrowsers = new ArrayList<>();

        // Chrome
        CustomBrowserImpl chromeBrowser = new CustomBrowserImpl();
        chromeBrowser.setName(getBuiltInBrowserName(Browser.CHROME));
        chromeBrowser.setBuiltIn(true);
        boolean driverAvailable = Browser.hasBundledWebDriver(Browser.CHROME);
        chromeBrowser.setDriverPath(
                getEffectiveDriverPath(
                        Browser.CHROME, seleniumOptions.getChromeDriverPath(), driverAvailable));
        chromeBrowser.setBinaryPath(seleniumOptions.getChromeBinaryPath());
        chromeBrowser.setBrowserType(CustomBrowserImpl.BrowserType.CHROMIUM);
        chromeArgumentsTableModel.setArguments(
                seleniumOptions.getBrowserArguments(Browser.CHROME.getId()));
        chromeBrowser.setArguments(chromeArgumentsTableModel.getElements());
        allBrowsers.add(chromeBrowser);

        // Edge
        CustomBrowserImpl edgeBrowser = new CustomBrowserImpl();
        edgeBrowser.setName(getBuiltInBrowserName(Browser.EDGE));
        edgeBrowser.setBuiltIn(true);
        driverAvailable = Browser.hasBundledWebDriver(Browser.EDGE);
        edgeBrowser.setDriverPath(
                getEffectiveDriverPath(
                        Browser.EDGE, seleniumOptions.getEdgeDriverPath(), driverAvailable));
        edgeBrowser.setBinaryPath(seleniumOptions.getEdgeBinaryPath());
        edgeBrowser.setBrowserType(CustomBrowserImpl.BrowserType.CHROMIUM);
        edgeArgumentsTableModel.setArguments(
                seleniumOptions.getBrowserArguments(Browser.EDGE.getId()));
        edgeBrowser.setArguments(edgeArgumentsTableModel.getElements());
        allBrowsers.add(edgeBrowser);

        // Firefox
        CustomBrowserImpl firefoxBrowser = new CustomBrowserImpl();
        firefoxBrowser.setName(getBuiltInBrowserName(Browser.FIREFOX));
        firefoxBrowser.setBuiltIn(true);
        driverAvailable = Browser.hasBundledWebDriver(Browser.FIREFOX);
        firefoxBrowser.setDriverPath(
                getEffectiveDriverPath(
                        Browser.FIREFOX, seleniumOptions.getFirefoxDriverPath(), driverAvailable));
        firefoxBrowser.setBinaryPath(seleniumOptions.getFirefoxBinaryPath());
        firefoxBrowser.setBrowserType(CustomBrowserImpl.BrowserType.FIREFOX);
        firefoxArgumentsTableModel.setArguments(
                seleniumOptions.getBrowserArguments(Browser.FIREFOX.getId()));
        firefoxBrowser.setArguments(firefoxArgumentsTableModel.getElements());
        allBrowsers.add(firefoxBrowser);

        // Add custom browsers
        allBrowsers.addAll(seleniumOptions.getCustomBrowsers());

        customBrowsersModel.setBrowsers(allBrowsers);
        browserExtModel.setExtensions(seleniumOptions.getBrowserExtensions());
        directory = seleniumOptions.getLastDirectory();
    }

    private static String getEffectiveDriverPath(
            Browser browser, String driverPath, boolean bundledDriverAvailable) {
        if (driverPath.isEmpty()) {
            if (bundledDriverAvailable) {
                return Browser.getBundledWebDriverPath(browser);
            }
            return "";
        }

        if (!Browser.isBundledWebDriverPath(driverPath)) {
            return driverPath;
        }

        if (!bundledDriverAvailable) {
            return "";
        }

        if (Files.exists(Paths.get(driverPath))) {
            return driverPath;
        }

        return Browser.getBundledWebDriverPath(browser);
    }

    @Override
    public void validateParam(Object obj) throws Exception {}

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam optionsParam = (OptionsParam) obj;
        SeleniumOptions seleniumOptions = optionsParam.getParamSet(SeleniumOptions.class);

        String chromeName = getBuiltInBrowserName(Browser.CHROME);
        String edgeName = getBuiltInBrowserName(Browser.EDGE);
        String firefoxName = getBuiltInBrowserName(Browser.FIREFOX);

        List<CustomBrowserImpl> allBrowsers = customBrowsersModel.getElements();
        List<CustomBrowserImpl> customBrowsers = new ArrayList<>();

        for (CustomBrowserImpl browser : allBrowsers) {
            if (browser.isBuiltIn()) {
                // Save built-in browsers (identified by their i18n'd names).
                if (chromeName.equals(browser.getName())) {
                    seleniumOptions.setChromeDriverPath(browser.getDriverPath());
                    seleniumOptions.setChromeBinaryPath(browser.getBinaryPath());
                    seleniumOptions.setBrowserArguments(
                            Browser.CHROME.getId(), browser.getArguments());
                } else if (edgeName.equals(browser.getName())) {
                    seleniumOptions.setEdgeDriverPath(browser.getDriverPath());
                    seleniumOptions.setEdgeBinaryPath(browser.getBinaryPath());
                    seleniumOptions.setBrowserArguments(
                            Browser.EDGE.getId(), browser.getArguments());
                } else if (firefoxName.equals(browser.getName())) {
                    seleniumOptions.setFirefoxDriverPath(browser.getDriverPath());
                    seleniumOptions.setFirefoxBinaryPath(browser.getBinaryPath());
                    seleniumOptions.setBrowserArguments(
                            Browser.FIREFOX.getId(), browser.getArguments());
                }
            } else {
                // Collect custom browsers
                customBrowsers.add(browser);
            }
        }

        seleniumOptions.setBrowserExtensions(browserExtModel.getElements());
        seleniumOptions.setCustomBrowsers(customBrowsers);
        seleniumOptions.setLastDirectory(directory);

        seleniumOptions.setConfirmRemoveBrowserArgument(confirmRemoveBrowserArgument.get());

        // Refresh custom browser providers after saving
        if (extSelenium != null) {
            extSelenium.registerCustomBrowsers();
        }
    }

    @Override
    public String getHelpIndex() {
        return "addon.selenium.options";
    }

    private static class BrowserExtMultipleOptionsPanel
            extends AbstractMultipleOptionsTablePanel<BrowserExtension> {
        private static final long serialVersionUID = 1L;

        private ResourceBundle resourceBundle;

        public BrowserExtMultipleOptionsPanel(
                AbstractMultipleOptionsTableModel<BrowserExtension> model,
                ResourceBundle resourceBundle) {
            super(model, false);
            this.resourceBundle = resourceBundle;

            getTable().setVisibleRowCount(5);
        }

        @Override
        public BrowserExtension showAddDialogue() {
            BrowserExtensionFileFilter fileFilter = BrowserExtension.getFileFilter();
            JFileChooser fileChooser =
                    new JFileChooser(directory) {
                        @Override
                        public void approveSelection() {
                            File selectedFile =
                                    fileFilter.getBrowserExtensionPath(getSelectedFile());
                            if (selectedFile == null) {
                                View.getSingleton()
                                        .showWarningDialog(
                                                BrowserExtMultipleOptionsPanel.this,
                                                resourceBundle.getString(
                                                        "selenium.browser.extentions.invalidpath"));
                                return;
                            }
                            setSelectedFile(selectedFile);
                            super.approveSelection();
                        }
                    };
            fileChooser.setFileFilter(fileFilter);
            fileChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
            if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                File file = fileChooser.getSelectedFile();
                directory = file.getParent();
                return new BrowserExtension(file.toPath());
            }
            return null;
        }

        @Override
        public BrowserExtension showModifyDialogue(BrowserExtension e) {
            // Not supported
            return null;
        }

        @Override
        public boolean showRemoveDialogue(BrowserExtension e) {
            JCheckBox removeWithoutConfirmationCheckBox =
                    new JCheckBox(
                            resourceBundle.getString(
                                    "selenium.options.dialog.remove.label.checkbox"));
            Object[] messages = {
                resourceBundle.getString("selenium.options.dialog.remove.text"),
                removeWithoutConfirmationCheckBox
            };
            int option =
                    JOptionPane.showOptionDialog(
                            this.getParent(),
                            messages,
                            resourceBundle.getString("selenium.options.dialog.remove.title"),
                            JOptionPane.OK_CANCEL_OPTION,
                            JOptionPane.QUESTION_MESSAGE,
                            null,
                            new String[] {
                                resourceBundle.getString(
                                        "selenium.options.dialog.remove.button.remove"),
                                resourceBundle.getString(
                                        "selenium.options.dialog.remove.button.cancel")
                            },
                            null);

            if (option == JOptionPane.OK_OPTION) {
                setRemoveWithoutConfirmation(removeWithoutConfirmationCheckBox.isSelected());

                return true;
            }

            return false;
        }
    }

    private static class CustomBrowsersMultipleOptionsPanel
            extends AbstractMultipleOptionsBaseTablePanel<CustomBrowserImpl> {
        private static final long serialVersionUID = 1L;

        private ResourceBundle resourceBundle;
        private Dialog parent;
        private DialogCustomBrowser addDialog;
        private DialogCustomBrowser modifyDialog;

        public CustomBrowsersMultipleOptionsPanel(
                AbstractMultipleOptionsBaseTableModel<CustomBrowserImpl> model,
                ResourceBundle resourceBundle,
                Dialog parent) {
            super(model, true);
            this.resourceBundle = resourceBundle;
            this.parent = parent;

            getTable().setVisibleRowCount(5);
        }

        @Override
        public CustomBrowserImpl showAddDialogue() {
            if (addDialog == null) {
                addDialog =
                        new DialogCustomBrowser(
                                parent,
                                resourceBundle.getString(
                                        "selenium.options.custom.browsers.dialog.add.title"));
                addDialog.pack();
            }
            // Reset dialog state for add mode
            addDialog.setCustomBrowser(null);
            addDialog.setExistingBrowsers(((CustomBrowsersTableModel) getModel()).getElements());
            addDialog.setVisible(true);

            // Get the browser if dialog was confirmed (user clicked OK)
            CustomBrowserImpl browser = addDialog.getCustomBrowser();
            addDialog.clear();

            // Only return browser if it was actually created (user clicked OK, not Cancel)
            return browser;
        }

        @Override
        public CustomBrowserImpl showModifyDialogue(CustomBrowserImpl e) {
            if (modifyDialog == null) {
                modifyDialog =
                        new DialogCustomBrowser(
                                parent,
                                resourceBundle.getString(
                                        "selenium.options.custom.browsers.dialog.modify.title"));
                modifyDialog.pack();
            }
            CustomBrowserImpl browserCopy = new CustomBrowserImpl(e);
            modifyDialog.setCustomBrowser(browserCopy);
            modifyDialog.setExistingBrowsers(((CustomBrowsersTableModel) getModel()).getElements());
            modifyDialog.setVisible(true);

            CustomBrowserImpl browser = modifyDialog.getCustomBrowser();
            modifyDialog.clear();

            // Return the browser if it was confirmed (not null) and has changes
            if (browser != null && !browser.allFieldsEqual(e)) {
                return browser;
            }

            return null;
        }

        @Override
        public boolean showRemoveDialogue(CustomBrowserImpl e) {
            if (e.isBuiltIn()) {
                // Built-in browsers cannot be removed - show warning
                JOptionPane.showMessageDialog(
                        this.getParent(),
                        resourceBundle.getString(
                                "selenium.options.custom.browsers.dialog.remove.builtin.warning"),
                        resourceBundle.getString(
                                "selenium.options.custom.browsers.dialog.remove.builtin.title"),
                        JOptionPane.WARNING_MESSAGE);
                return false;
            }

            JCheckBox removeWithoutConfirmationCheckBox =
                    new JCheckBox(
                            resourceBundle.getString(
                                    "selenium.options.dialog.remove.label.checkbox"));
            Object[] messages = {
                resourceBundle.getString("selenium.options.custom.browsers.dialog.remove.text"),
                removeWithoutConfirmationCheckBox
            };
            int option =
                    JOptionPane.showOptionDialog(
                            this.getParent(),
                            messages,
                            resourceBundle.getString(
                                    "selenium.options.custom.browsers.dialog.remove.title"),
                            JOptionPane.OK_CANCEL_OPTION,
                            JOptionPane.QUESTION_MESSAGE,
                            null,
                            new String[] {
                                resourceBundle.getString(
                                        "selenium.options.dialog.remove.button.remove"),
                                resourceBundle.getString(
                                        "selenium.options.dialog.remove.button.cancel")
                            },
                            null);

            if (option == JOptionPane.OK_OPTION) {
                setRemoveWithoutConfirmation(removeWithoutConfirmationCheckBox.isSelected());

                return true;
            }

            return false;
        }
    }
}
