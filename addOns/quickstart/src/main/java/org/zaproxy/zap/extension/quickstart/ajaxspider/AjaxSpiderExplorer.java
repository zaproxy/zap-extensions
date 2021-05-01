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

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URI;
import java.util.Optional;
import javax.swing.Box;
import javax.swing.ComboBoxModel;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.model.Model;
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

    private ExtensionQuickStartAjaxSpider extension;
    private JCheckBox selectCheckBox;
    private JComboBox<ProvidedBrowserUI> browserComboBox;
    private JPanel panel;

    public AjaxSpiderExplorer(ExtensionQuickStartAjaxSpider extension) {
        this.extension = extension;
    }

    public ExtensionAjax getExtAjax() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionAjax.class);
    }

    @Override
    public void startScan(URI uri) {
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

    @Override
    public void stopScan() {
        this.getExtAjax().stopScan();
    }

    @Override
    public String getLabel() {
        return Constant.messages.getString("quickstart.label.ajaxspider");
    }

    private JCheckBox getSelectCheckBox() {
        if (selectCheckBox == null) {
            selectCheckBox = new JCheckBox();
            selectCheckBox.addActionListener(
                    new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent arg0) {
                            getBrowserComboBox().setEnabled(selectCheckBox.isSelected());
                            extension
                                    .getExtQuickStart()
                                    .getQuickStartParam()
                                    .setAjaxSpiderEnabled(selectCheckBox.isSelected());
                        }
                    });
        }
        return selectCheckBox;
    }

    private JComboBox<ProvidedBrowserUI> getBrowserComboBox() {
        if (browserComboBox == null) {
            browserComboBox = new JComboBox<ProvidedBrowserUI>();
            ProvidedBrowsersComboBoxModel model =
                    extension.getExtSelenium().createProvidedBrowsersComboBoxModel();
            model.setIncludeUnconfigured(false);
            browserComboBox.setModel(model);
            browserComboBox.addActionListener(
                    new ActionListener() {

                        @Override
                        public void actionPerformed(ActionEvent arg0) {
                            extension
                                    .getExtQuickStart()
                                    .getQuickStartParam()
                                    .setAjaxSpiderDefaultBrowser(
                                            browserComboBox.getSelectedItem().toString());
                        }
                    });

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
                    getSelectCheckBox(),
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
        return getSelectCheckBox().isSelected();
    }

    @Override
    public boolean isRunning() {
        return this.getExtAjax().isSpiderRunning();
    }

    public void optionsLoaded(QuickStartParam quickStartParam) {
        getSelectCheckBox().setSelected(quickStartParam.isAjaxSpiderEnabled());
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
}
