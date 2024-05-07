/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.quickstart.ajaxspider;

import java.net.URI;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import javax.swing.Box;
import javax.swing.ComboBoxModel;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.alert.AlertEventPublisher;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.quickstart.PlugableSpider;
import org.zaproxy.zap.extension.quickstart.QuickStartBackgroundPanel;
import org.zaproxy.zap.extension.quickstart.QuickStartParam;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.ProvidedBrowserUI;
import org.zaproxy.zap.extension.selenium.ProvidedBrowsersComboBoxModel;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderParam;
import org.zaproxy.zap.extension.spiderAjax.AjaxSpiderTarget;
import org.zaproxy.zap.extension.spiderAjax.ExtensionAjax;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.LayoutHelper;

public class AjaxSpiderExplorer implements PlugableSpider {

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

    private ExtensionQuickStartAjaxSpider extension;
    private JComboBox<ProvidedBrowserUI> browserComboBox;
    private JComboBox<Select> selectComboBox;
    private EventConsumerImpl eventConsumer;
    private boolean isModern;

    private JPanel panel;

    public AjaxSpiderExplorer(ExtensionQuickStartAjaxSpider extension) {
        this.extension = extension;
    }

    @Override
    public void init() {
        isModern = false;
        eventConsumer = new EventConsumerImpl();
        ZAP.getEventBus()
                .registerConsumer(
                        eventConsumer,
                        AlertEventPublisher.getPublisher().getPublisherName(),
                        AlertEventPublisher.ALERT_ADDED_EVENT);
    }

    public ExtensionAjax getExtAjax() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionAjax.class);
    }

    public ExtensionPassiveScan getExtPscan() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionPassiveScan.class);
    }

    @Override
    public void startScan(URI uri) {
        int selInd = this.getSelectComboBox().getSelectedIndex();
        if (selInd == Select.NEVER.getIndex()) {
            ZAP.getEventBus().unregisterConsumer(eventConsumer);
            return;
        }
        if (selInd == Select.MODERN.getIndex()) {
            // Only run if modern - keep monitoring for the relevant alert until the passive scan
            // queue empties
            ExtensionPassiveScan extPscan = this.getExtPscan();
            while (extPscan.getRecordsToScan() > 0) {
                if (isModern) {
                    break;
                }
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    // Ignore
                }
            }
            if (!isModern) {
                ZAP.getEventBus().unregisterConsumer(eventConsumer);
                return;
            }
        }
        ZAP.getEventBus().unregisterConsumer(eventConsumer);

        ExtensionAjax extAjax = this.getExtAjax();
        AjaxSpiderParam options =
                Model.getSingleton().getOptionsParam().getParamSet(AjaxSpiderParam.class).clone();
        ProvidedBrowserUI browserUi = (ProvidedBrowserUI) getBrowserComboBox().getSelectedItem();
        options.setBrowserId(browserUi.getBrowser().getId());
        AjaxSpiderTarget.Builder builder =
                AjaxSpiderTarget.newBuilder(extension.getModel().getSession());
        builder.setStartUri(uri);
        builder.setInScopeOnly(false);
        builder.setSubtreeOnly(false);
        builder.setOptions(options);
        extAjax.startScan(builder.build());
    }

    /** Monitors the alert added events for the Modern App Detection rule: 10109. */
    private class EventConsumerImpl implements EventConsumer {
        @Override
        public void eventReceived(Event event) {
            if (isModern) {
                // No need to check anything
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
        this.getExtAjax().stopScan();
    }

    @Override
    public String getLabel() {
        return Constant.messages.getString("quickstart.label.ajaxspider");
    }

    private JComboBox<Select> getSelectComboBox() {
        if (selectComboBox == null) {
            selectComboBox = new JComboBox<>();
            Stream.of(Select.values()).forEach(s -> selectComboBox.addItem(s));
            selectComboBox.addActionListener(
                    e ->
                            extension
                                    .getExtQuickStart()
                                    .getQuickStartParam()
                                    .setAjaxSpiderSelection(
                                            ((Select) selectComboBox.getSelectedItem()).name()));
        }
        return selectComboBox;
    }

    private JComboBox<ProvidedBrowserUI> getBrowserComboBox() {
        if (browserComboBox == null) {
            browserComboBox = new JComboBox<>();
            ProvidedBrowsersComboBoxModel model =
                    extension.getExtSelenium().createProvidedBrowsersComboBoxModel();
            model.setIncludeUnconfigured(false);
            browserComboBox.setModel(model);
            browserComboBox.addActionListener(
                    e ->
                            extension
                                    .getExtQuickStart()
                                    .getQuickStartParam()
                                    .setAjaxSpiderDefaultBrowser(
                                            browserComboBox.getSelectedItem().toString()));

            String defaultBrowserId = Browser.FIREFOX_HEADLESS.getId();
            Optional<ProvidedBrowserUI> defaultItem =
                    extension.getExtSelenium().getProvidedBrowserUIList().stream()
                            .filter(e -> defaultBrowserId.equals(e.getBrowser().getId()))
                            .findFirst();
            if (defaultItem.isPresent()) {
                browserComboBox.setSelectedItem(defaultItem.get());
            }
        }
        return browserComboBox;
    }

    @Override
    public JPanel getPanel() {
        if (panel == null) {
            panel = new QuickStartBackgroundPanel();
            panel.add(
                    getSelectComboBox(),
                    LayoutHelper.getGBC(0, 0, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
            panel.add(
                    new JLabel(Constant.messages.getString("quickstart.label.withbrowser")),
                    LayoutHelper.getGBC(1, 0, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
            panel.add(
                    getBrowserComboBox(),
                    LayoutHelper.getGBC(2, 0, 1, 0.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
            panel.add(
                    new JLabel(""),
                    LayoutHelper.getGBC(3, 0, 1, 1.0D, DisplayUtils.getScaledInsets(5, 5, 5, 5)));
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
        return this.getExtAjax().isSpiderRunning();
    }

    @Override
    public void setEnabled(boolean val) {
        // Nothing to do
    }

    public void optionsLoaded(QuickStartParam quickStartParam) {
        Select select = Select.MODERN;
        try {
            select = Select.valueOf(quickStartParam.getAjaxSpiderSelection());
        } catch (Exception e) {
            // Ignore
        }
        getSelectComboBox().setSelectedItem(select);
        String def = quickStartParam.getAjaxSpiderDefaultBrowser();
        if (def == null || def.length() == 0) {
            // no default
            return;
        }
        ComboBoxModel<ProvidedBrowserUI> model = this.getBrowserComboBox().getModel();
        for (int idx = 0; idx < model.getSize(); idx++) {
            ProvidedBrowserUI el = model.getElementAt(idx);
            if (el.getName().equals(def)) {
                model.setSelectedItem(el);
                break;
            }
        }
    }

    @Override
    public boolean requireStdSpider() {
        return this.getSelectComboBox().getSelectedIndex() != Select.ALWAYS.getIndex();
    }
}
