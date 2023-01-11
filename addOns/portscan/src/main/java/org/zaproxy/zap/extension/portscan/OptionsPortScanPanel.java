/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2010 The ZAP Development Team
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
package org.zaproxy.zap.extension.portscan;

import java.awt.CardLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSlider;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.commonlib.Constants;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.utils.ZapPortNumberSpinner;
import org.zaproxy.zap.view.LayoutHelper;

public class OptionsPortScanPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;
    private JPanel panelPortScan = null;
    private ZapPortNumberSpinner maxPortValueSpinner = null;
    private ZapNumberSpinner threadsPerScanSpinner = null;
    private JSlider sliderTimeoutInMs = null;
    private JCheckBox checkUseProxy = null;

    public OptionsPortScanPanel() {
        super();
        this.setLayout(new CardLayout());
        this.setName(Constant.messages.getString("ports.options.title"));
        this.add(getPanelPortScan(), getPanelPortScan().getName());
    }

    /**
     * This method initializes panelPortScan
     *
     * @return javax.swing.JPanel
     */
    private JPanel getPanelPortScan() {
        if (panelPortScan == null) {
            panelPortScan = new JPanel();
            panelPortScan.setLayout(new GridBagLayout());
            panelPortScan.setName("");

            JPanel panelProxy = new JPanel();

            panelPortScan.add(
                    new JLabel(Constant.messages.getString("ports.options.label.maxPort")),
                    LayoutHelper.getGBC(
                            0,
                            0,
                            1,
                            1.0D,
                            0,
                            GridBagConstraints.HORIZONTAL,
                            new Insets(2, 2, 2, 2)));
            panelPortScan.add(
                    getMaxPortSpinner(),
                    LayoutHelper.getGBC(
                            1,
                            0,
                            1,
                            1.0D,
                            0,
                            GridBagConstraints.HORIZONTAL,
                            new Insets(2, 2, 2, 2)));

            panelPortScan.add(
                    new JLabel(Constant.messages.getString("ports.options.label.threads")),
                    LayoutHelper.getGBC(
                            0,
                            1,
                            1,
                            1.0D,
                            0,
                            GridBagConstraints.HORIZONTAL,
                            new Insets(2, 2, 2, 2)));
            panelPortScan.add(
                    getThreadsPerScanSpinner(),
                    LayoutHelper.getGBC(
                            1,
                            1,
                            1,
                            1.0D,
                            0,
                            GridBagConstraints.HORIZONTAL,
                            new Insets(2, 2, 2, 2)));

            panelPortScan.add(
                    new JLabel(Constant.messages.getString("ports.options.label.timeoutInMs")),
                    LayoutHelper.getGBC(
                            0,
                            2,
                            2,
                            1.0D,
                            0,
                            GridBagConstraints.HORIZONTAL,
                            new Insets(2, 2, 2, 2)));
            panelPortScan.add(
                    getSliderTimeoutInMs(),
                    LayoutHelper.getGBC(
                            0,
                            3,
                            2,
                            1.0D,
                            0,
                            GridBagConstraints.HORIZONTAL,
                            new Insets(2, 2, 2, 2)));

            panelProxy.add(new JLabel(Constant.messages.getString("ports.options.label.useProxy")));
            panelProxy.add(getCheckUseProxy());

            panelPortScan.add(
                    panelProxy,
                    LayoutHelper.getGBC(
                            0, 4, 2, 1.0D, 0, GridBagConstraints.WEST, new Insets(2, 2, 2, 2)));

            panelPortScan.add(
                    new JLabel(""),
                    LayoutHelper.getGBC(
                            0,
                            5,
                            2,
                            1.0D,
                            1.0D,
                            GridBagConstraints.HORIZONTAL,
                            new Insets(2, 2, 2, 2)));
        }
        return panelPortScan;
    }

    @Override
    public void initParam(Object obj) {
        OptionsParam options = (OptionsParam) obj;
        PortScanParam param = options.getParamSet(PortScanParam.class);
        if (param == null) {
            getMaxPortSpinner().setValue(PortScanParam.DEFAULT_MAX_PORT);
            getThreadsPerScanSpinner().setValue(Constants.getDefaultThreadCount());
            getSliderTimeoutInMs().setValue(PortScanParam.DEFAULT_TIMEOUT_IN_MS);
            getCheckUseProxy().setSelected(PortScanParam.DEFAULT_USE_PROXY);
        } else {
            getMaxPortSpinner().setValue(param.getMaxPort());
            getThreadsPerScanSpinner().setValue(param.getThreadPerScan());
            getSliderTimeoutInMs().setValue(param.getTimeoutInMs());
            getCheckUseProxy().setSelected(param.isUseProxy());
        }
    }

    @Override
    public void validateParam(Object obj) {
        // no validation needed
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        OptionsParam options = (OptionsParam) obj;
        PortScanParam param = options.getParamSet(PortScanParam.class);
        if (param == null) {
            param = new PortScanParam();
            options.addParamSet(param);
        }
        param.setMaxPort(getMaxPortSpinner().getValue());
        param.setThreadPerScan(getThreadsPerScanSpinner().getValue());
        param.setTimeoutInMs(getSliderTimeoutInMs().getValue());
        param.setUseProxy(getCheckUseProxy().isSelected());
    }

    private ZapPortNumberSpinner getMaxPortSpinner() {
        if (maxPortValueSpinner == null) {
            maxPortValueSpinner = new ZapPortNumberSpinner(PortScanParam.DEFAULT_MAX_PORT);
        }
        return maxPortValueSpinner;
    }

    private ZapNumberSpinner getThreadsPerScanSpinner() {
        if (threadsPerScanSpinner == null) {
            threadsPerScanSpinner =
                    new ZapNumberSpinner(1, Constants.getDefaultThreadCount(), Integer.MAX_VALUE);
        }
        return threadsPerScanSpinner;
    }

    private JSlider getSliderTimeoutInMs() {
        if (sliderTimeoutInMs == null) {
            sliderTimeoutInMs = new JSlider();
            sliderTimeoutInMs.setMaximum(1000);
            sliderTimeoutInMs.setMinimum(0);
            sliderTimeoutInMs.setValue(200);
            sliderTimeoutInMs.setPaintTicks(true);
            sliderTimeoutInMs.setPaintLabels(true);
            sliderTimeoutInMs.setMinorTickSpacing(20);
            sliderTimeoutInMs.setMajorTickSpacing(100);
            sliderTimeoutInMs.setSnapToTicks(true);
            sliderTimeoutInMs.setPaintTrack(true);
        }
        return sliderTimeoutInMs;
    }

    public int getThreadPerScan() {
        return this.threadsPerScanSpinner.getValue();
    }

    public int getMaxPort() {
        return this.maxPortValueSpinner.getValue();
    }

    public JCheckBox getCheckUseProxy() {
        if (checkUseProxy == null) {
            checkUseProxy = new JCheckBox();
        }
        return checkUseProxy;
    }

    @Override
    public String getHelpIndex() {
        return "addon.portscan.options";
    }
}
