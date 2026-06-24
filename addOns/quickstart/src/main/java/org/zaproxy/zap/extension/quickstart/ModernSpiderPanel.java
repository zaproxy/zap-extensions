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

import java.awt.BorderLayout;
import java.net.URI;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;
import javax.swing.Box;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.alert.AlertEventPublisher;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.LayoutHelper;

/** The modern spider row in the Quick Start attack panel. */
public class ModernSpiderPanel implements PlugableSpider {

    public enum Select {
        NEVER(0),
        MODERN(1),
        ALWAYS(2);

        private int index;

        private Select(int idx) {
            index = idx;
        }

        public int getIndex() {
            return index;
        }

        @Override
        public String toString() {
            return Constant.messages.getString(
                    "quickstart.select." + name().toLowerCase(Locale.ROOT));
        }
    }

    private static final String MODERN_APP_PLUGIN_ID = "10109";

    private final ExtensionQuickStart extension;
    private JComboBox<Select> selectComboBox;
    private DefaultComboBoxModel<ModernSpiderOption> typeComboModel;
    private JComboBox<ModernSpiderOption> typeComboBox;
    private BrowserSelector browserSelector;
    private JPanel browserContainer;
    private EventConsumerImpl eventConsumer;
    private boolean isModern;
    private volatile boolean stopRequested;
    private ModernSpiderOption activeOption;
    private QuickStartParam loadedParam;

    private JPanel panel;

    public ModernSpiderPanel(ExtensionQuickStart extension) {
        this.extension = extension;
    }

    @Override
    public void init() {
        isModern = false;
        stopRequested = false;
        eventConsumer = new EventConsumerImpl();
        ZAP.getEventBus()
                .registerConsumer(
                        eventConsumer,
                        AlertEventPublisher.getPublisher().getPublisherName(),
                        AlertEventPublisher.ALERT_ADDED_EVENT);
    }

    private ExtensionPassiveScan2 getExtPscan() {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionPassiveScan2.class);
    }

    public void setBrowserSelector(BrowserSelector selector) {
        this.browserSelector = selector;
        JPanel container = getBrowserContainer();
        container.removeAll();
        if (selector != null) {
            container.add(selector.getComponent(), BorderLayout.CENTER);
            if (loadedParam != null) {
                selector.restoreSelection(loadedParam.getAjaxSpiderDefaultBrowser());
            }
        }
        container.revalidate();
        container.repaint();
    }

    private JPanel getBrowserContainer() {
        if (browserContainer == null) {
            browserContainer = new JPanel(new BorderLayout());
        }
        return browserContainer;
    }

    public void addOption(ModernSpiderOption option) {
        getTypeComboModel().addElement(option);
        if (loadedParam != null) {
            String savedType = loadedParam.getModernSpiderType();
            if (savedType != null && option.getName().equals(savedType)) {
                getTypeComboModel().setSelectedItem(option);
            }
        }
    }

    public void removeOption(ModernSpiderOption option) {
        getTypeComboModel().removeElement(option);
    }

    public int getOptionCount() {
        return getTypeComboModel().getSize();
    }

    DefaultComboBoxModel<ModernSpiderOption> getTypeComboModel() {
        if (typeComboModel == null) {
            typeComboModel = new DefaultComboBoxModel<>();
        }
        return typeComboModel;
    }

    @Override
    public void startScan(URI uri) {
        int selInd = this.getSelectComboBox().getSelectedIndex();

        QuickStartParam qsParam = extension.getQuickStartParam();
        qsParam.setAjaxSpiderSelection(((Select) selectComboBox.getSelectedItem()).name());
        if (browserSelector != null) {
            qsParam.setAjaxSpiderDefaultBrowser(browserSelector.getSelectedBrowserName());
        }
        ModernSpiderOption selected = (ModernSpiderOption) getTypeComboBox().getSelectedItem();
        if (selected != null) {
            qsParam.setModernSpiderType(selected.getName());
        }

        if (selInd == Select.NEVER.getIndex()) {
            ZAP.getEventBus().unregisterConsumer(eventConsumer);
            return;
        }
        if (selInd == Select.MODERN.getIndex()) {
            ExtensionPassiveScan2 extPscan = getExtPscan();
            while (!stopRequested && extPscan.getRecordsToScan() > 0) {
                if (isModern) {
                    break;
                }
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            if (stopRequested || !isModern) {
                ZAP.getEventBus().unregisterConsumer(eventConsumer);
                return;
            }
        }
        ZAP.getEventBus().unregisterConsumer(eventConsumer);

        if (selected == null || browserSelector == null || stopRequested) {
            return;
        }
        String browserId = browserSelector.getSelectedBrowserId();
        if (browserId == null) {
            return;
        }
        activeOption = selected;
        activeOption.startScan(uri, browserId);
    }

    /** Monitors the alert added events for the Modern App Detection rule: 10109. */
    private class EventConsumerImpl implements EventConsumer {
        @Override
        public void eventReceived(Event event) {
            if (isModern) {
                return;
            } else if (event.getEventType().equals(AlertEventPublisher.ALERT_ADDED_EVENT)) {
                Map<String, String> params = event.getParameters();
                if (MODERN_APP_PLUGIN_ID.equals(params.get(AlertEventPublisher.PLUGIN_ID))) {
                    isModern = true;
                }
            }
        }
    }

    @Override
    public void stopScan() {
        stopRequested = true;
        if (activeOption != null) {
            activeOption.stopScan();
        }
    }

    @Override
    public String getLabel() {
        return Constant.messages.getString("quickstart.label.modernspider");
    }

    private JComboBox<Select> getSelectComboBox() {
        if (selectComboBox == null) {
            selectComboBox = new JComboBox<>();
            Stream.of(Select.values()).forEach(s -> selectComboBox.addItem(s));
        }
        return selectComboBox;
    }

    private JComboBox<ModernSpiderOption> getTypeComboBox() {
        if (typeComboBox == null) {
            typeComboBox = new JComboBox<>(getTypeComboModel());
        }
        return typeComboBox;
    }

    @Override
    public JPanel getPanel() {
        if (panel == null) {
            panel = new QuickStartBackgroundPanel();
            panel.add(
                    getTypeComboBox(),
                    LayoutHelper.getGBC(0, 0, 1, 0.0D, DisplayUtils.getScaledInsets(5, 0, 5, 5)));
            panel.add(
                    new JLabel(Constant.messages.getString("quickstart.label.withbrowser")),
                    LayoutHelper.getGBC(1, 0, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
            panel.add(
                    getBrowserContainer(),
                    LayoutHelper.getGBC(2, 0, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
            panel.add(
                    getSelectComboBox(),
                    LayoutHelper.getGBC(3, 0, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
            panel.add(
                    new JLabel(""),
                    LayoutHelper.getGBC(4, 0, 1, 1.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
            panel.add(Box.createHorizontalGlue());
        }
        return panel;
    }

    @Override
    public boolean isSelected() {
        // Always 'enabled', as this class decides if it runs or not
        return true;
    }

    @Override
    public boolean isRunning() {
        return activeOption != null && activeOption.isRunning();
    }

    @Override
    public void setEnabled(boolean val) {
        // Nothing to do
    }

    public void optionsLoaded(QuickStartParam quickStartParam) {
        this.loadedParam = quickStartParam;

        Select select = Select.MODERN;
        try {
            select = Select.valueOf(quickStartParam.getAjaxSpiderSelection());
        } catch (Exception e) {
            // Ignore
        }
        getSelectComboBox().setSelectedItem(select);

        if (browserSelector != null) {
            browserSelector.restoreSelection(quickStartParam.getAjaxSpiderDefaultBrowser());
        }

        String savedType = quickStartParam.getModernSpiderType();
        if (savedType != null && !savedType.isEmpty()) {
            DefaultComboBoxModel<ModernSpiderOption> model = getTypeComboModel();
            for (int idx = 0; idx < model.getSize(); idx++) {
                ModernSpiderOption opt = model.getElementAt(idx);
                if (opt.getName().equals(savedType)) {
                    model.setSelectedItem(opt);
                    break;
                }
            }
        }
    }

    @Override
    public boolean requireStdSpider() {
        return this.getSelectComboBox().getSelectedIndex() != Select.ALWAYS.getIndex();
    }
}
