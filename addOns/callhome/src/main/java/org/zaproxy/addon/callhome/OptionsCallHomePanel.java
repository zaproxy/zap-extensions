/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.callhome;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.EmptyBorder;
import net.sf.json.JSONObject;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.utils.ZapTextArea;
import org.zaproxy.zap.view.LayoutHelper;

@SuppressWarnings("serial")
public class OptionsCallHomePanel extends AbstractParamPanel {

    private static final long serialVersionUID = -7541236934312940852L;

    private static final String NAME = Constant.messages.getString("callhome.optionspanel.name");

    private ExtensionCallHome ext;
    private JCheckBox telemetryEnabledBox;
    private ZapTextArea lastTelemetryDataBox;

    public OptionsCallHomePanel(ExtensionCallHome ext) {
        super();
        setName(NAME);
        this.ext = ext;

        setLayout(new GridBagLayout());

        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(2, 2, 2, 2));

        int y = 0;
        panel.add(
                getTelemetryEnabledBox(),
                LayoutHelper.getGBC(0, y++, 1, 1.0, new Insets(2, 2, 2, 2)));

        JLabel lastTelemetryDataLabel =
                new JLabel(Constant.messages.getString("callhome.optionspanel.label.tellastdata"));
        lastTelemetryDataLabel.setLabelFor(getLastTelemetryDataBox());
        panel.add(
                lastTelemetryDataLabel,
                LayoutHelper.getGBC(0, y++, 1, 1.0, new Insets(2, 2, 2, 2)));

        JScrollPane scrollPane = new JScrollPane(getLastTelemetryDataBox());
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS);
        scrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        panel.add(
                scrollPane,
                LayoutHelper.getGBC(0, y++, 1, 1.0, 1.0, GridBagConstraints.BOTH, getInsets()));

        add(panel, LayoutHelper.getGBC(0, 0, 1, 1.0, 1.0));
    }

    private JCheckBox getTelemetryEnabledBox() {
        if (telemetryEnabledBox == null) {
            telemetryEnabledBox = new JCheckBox();
            telemetryEnabledBox.setText(
                    Constant.messages.getString("callhome.optionspanel.label.telenabled"));
        }
        return telemetryEnabledBox;
    }

    private ZapTextArea getLastTelemetryDataBox() {
        if (lastTelemetryDataBox == null) {
            lastTelemetryDataBox = new ZapTextArea();
            lastTelemetryDataBox.setEditable(false);
        }
        return lastTelemetryDataBox;
    }

    @Override
    public void initParam(Object obj) {
        final OptionsParam options = (OptionsParam) obj;
        final CallHomeParam param = options.getParamSet(CallHomeParam.class);

        getTelemetryEnabledBox().setSelected(param.isTelemetryEnabled());
        JSONObject data = ext.getLastTelemetryData();
        if (data == null) {
            getLastTelemetryDataBox().setText("");
        } else {
            getLastTelemetryDataBox().setText(data.toString(4));
        }
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        final OptionsParam options = (OptionsParam) obj;
        final CallHomeParam param = options.getParamSet(CallHomeParam.class);

        param.setTelemetryEnabled(getTelemetryEnabledBox().isSelected());
    }

    @Override
    public String getHelpIndex() {
        return "callhome";
    }
}
