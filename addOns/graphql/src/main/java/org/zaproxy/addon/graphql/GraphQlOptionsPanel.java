/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.graphql;

import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.Box;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.TitledBorder;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.graphql.GraphQlParam.ArgsTypeOption;
import org.zaproxy.addon.graphql.GraphQlParam.CycleDetectionModeOption;
import org.zaproxy.addon.graphql.GraphQlParam.QuerySplitOption;
import org.zaproxy.addon.graphql.GraphQlParam.RequestMethodOption;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.view.LayoutHelper;

/** The GraphQL options panel. */
public class GraphQlOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    /** The name of the options panel. */
    private static final String NAME = Constant.messages.getString("graphql.options.panelName");

    private JCheckBox queryGenEnabled;
    private JPanel importConfigPanel;
    private JPanel queryGenConfigPanel;
    private JPanel cycleDetectionConfigPanel;
    private ZapNumberSpinner maxQueryDepthNumberSpinner;
    private JCheckBox lenientMaxQueryDepthEnabled = null;
    private ZapNumberSpinner maxAdditionalQueryDepthNumberSpinner;
    private ZapNumberSpinner maxArgsDepthNumberSpinner;
    private JCheckBox optionalArgsEnabled = null;
    private JComboBox<ArgsTypeOption> argsTypeOptions = null;
    private JComboBox<QuerySplitOption> querySplitOptions = null;
    private JComboBox<RequestMethodOption> requestMethodOptions = null;
    private JLabel maxAdditionalQueryDepthLabel;
    private JComboBox<CycleDetectionModeOption> cycleDetectionModeOptions;
    private ZapNumberSpinner maxCycleDetectionAlertsNumberSpinner;

    public GraphQlOptionsPanel() {
        super();
        setName(NAME);
        setLayout(new GridBagLayout());

        int y = -1;
        add(getImportConfigPanel(), LayoutHelper.getGBC(0, ++y, 1, 1.0, new Insets(10, 2, 2, 2)));
        add(getQueryGenConfigPanel(), LayoutHelper.getGBC(0, ++y, 1, 1.0, new Insets(2, 2, 2, 2)));
        add(
                getCycleDetectionConfigPanel(),
                LayoutHelper.getGBC(0, ++y, 1, 1.0, new Insets(2, 2, 2, 2)));
        add(Box.createGlue(), LayoutHelper.getGBC(0, ++y, 1, 1.0, 1.0));
    }

    @Override
    public void initParam(Object obj) {
        final OptionsParam options = (OptionsParam) obj;
        final GraphQlParam param = options.getParamSet(GraphQlParam.class);

        getQueryGenEnabled().setSelected(param.getQueryGenEnabled());
        getMaxQueryDepthNumberSpinner().setValue(param.getMaxQueryDepth());
        getLenientMaxQueryDepthEnabled().setSelected(param.getLenientMaxQueryDepthEnabled());
        getMaxAdditionalQueryDepthNumberSpinner().setValue(param.getMaxAdditionalQueryDepth());
        getMaxArgsDepthNumberSpinner().setValue(param.getMaxArgsDepth());
        getOptionalArgsEnabled().setSelected(param.getOptionalArgsEnabled());
        getArgsTypeOptions().setSelectedItem(param.getArgsType());
        getQuerySplitOptions().setSelectedItem(param.getQuerySplitType());
        getRequestMethodOptions().setSelectedItem(param.getRequestMethod());
        getCycleDetectionModeOptions().setSelectedItem(param.getCycleDetectionMode());
        getMaxCycleDetectionAlertsNumberSpinner().setValue(param.getMaxCycleDetectionAlerts());
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        final OptionsParam options = (OptionsParam) obj;
        final GraphQlParam param = options.getParamSet(GraphQlParam.class);

        param.setQueryGenEnabled(getQueryGenEnabled().isSelected());
        param.setMaxQueryDepth(getMaxQueryDepthNumberSpinner().getValue());
        param.setLenientMaxQueryDepthEnabled(getLenientMaxQueryDepthEnabled().isSelected());
        param.setMaxAdditionalQueryDepth(getMaxAdditionalQueryDepthNumberSpinner().getValue());
        param.setMaxArgsDepth(getMaxArgsDepthNumberSpinner().getValue());
        param.setOptionalArgsEnabled(getOptionalArgsEnabled().isSelected());
        param.setArgsType((ArgsTypeOption) getArgsTypeOptions().getSelectedItem());
        param.setQuerySplitType((QuerySplitOption) getQuerySplitOptions().getSelectedItem());
        param.setRequestMethod((RequestMethodOption) getRequestMethodOptions().getSelectedItem());
        param.setCycleDetectionMode(
                (CycleDetectionModeOption) getCycleDetectionModeOptions().getSelectedItem());
        param.setMaxCycleDetectionAlerts(getMaxCycleDetectionAlertsNumberSpinner().getValue());
    }

    private JCheckBox getQueryGenEnabled() {
        if (queryGenEnabled == null) {
            queryGenEnabled =
                    new JCheckBox(
                            Constant.messages.getString("graphql.options.label.queryGenEnabled"),
                            true);
        }
        return queryGenEnabled;
    }

    private JPanel getImportConfigPanel() {
        if (importConfigPanel == null) {
            importConfigPanel = new JPanel(new GridBagLayout());
            importConfigPanel.setBorder(
                    new TitledBorder(
                            Constant.messages.getString(
                                    "graphql.options.importConfigPanel.title")));
            int y = -1;
            importConfigPanel.add(
                    getQueryGenEnabled(),
                    LayoutHelper.getGBC(0, ++y, 2, 1.0, new Insets(2, 2, 2, 2)));
        }
        return importConfigPanel;
    }

    private JPanel getQueryGenConfigPanel() {
        if (queryGenConfigPanel == null) {
            queryGenConfigPanel = new JPanel(new GridBagLayout());
            queryGenConfigPanel.setBorder(
                    new TitledBorder(
                            Constant.messages.getString(
                                    "graphql.options.queryGenConfigPanel.title")));

            JLabel maxQueryDepthLabel =
                    new JLabel(Constant.messages.getString("graphql.options.label.queryDepth"));
            JLabel maxArgsDepthLabel =
                    new JLabel(Constant.messages.getString("graphql.options.label.argsDepth"));
            JLabel argsTypeLabel =
                    new JLabel(Constant.messages.getString("graphql.options.label.argsType"));
            JLabel splitQueryLabel =
                    new JLabel(Constant.messages.getString("graphql.options.label.split"));
            JLabel requestMethodLabel =
                    new JLabel(Constant.messages.getString("graphql.options.label.requestMethod"));

            int i = -1;
            queryGenConfigPanel.add(
                    maxQueryDepthLabel,
                    LayoutHelper.getGBC(0, ++i, 1, 1.0, new Insets(2, 2, 2, 2)));
            queryGenConfigPanel.add(
                    getMaxQueryDepthNumberSpinner(),
                    LayoutHelper.getGBC(1, i, 1, 1.0, new Insets(2, 2, 2, 2)));
            queryGenConfigPanel.add(
                    getLenientMaxQueryDepthEnabled(),
                    LayoutHelper.getGBC(0, ++i, 2, 1.0, new Insets(2, 2, 2, 2)));
            queryGenConfigPanel.add(
                    getMaxAdditionalQueryDepthLabel(),
                    LayoutHelper.getGBC(0, ++i, 1, 1.0, new Insets(2, 2, 2, 2)));
            queryGenConfigPanel.add(
                    getMaxAdditionalQueryDepthNumberSpinner(),
                    LayoutHelper.getGBC(1, i, 1, 1.0, new Insets(2, 2, 2, 2)));
            queryGenConfigPanel.add(
                    maxArgsDepthLabel, LayoutHelper.getGBC(0, ++i, 1, 1.0, new Insets(2, 2, 2, 2)));
            queryGenConfigPanel.add(
                    getMaxArgsDepthNumberSpinner(),
                    LayoutHelper.getGBC(1, i, 1, 1.0, new Insets(2, 2, 2, 2)));
            queryGenConfigPanel.add(
                    getOptionalArgsEnabled(),
                    LayoutHelper.getGBC(0, ++i, 2, 1.0, new Insets(2, 2, 2, 2)));
            queryGenConfigPanel.add(
                    argsTypeLabel, LayoutHelper.getGBC(0, ++i, 1, 1.0, new Insets(2, 2, 2, 2)));
            queryGenConfigPanel.add(
                    getArgsTypeOptions(),
                    LayoutHelper.getGBC(1, i, 1, 1.0, new Insets(2, 2, 2, 2)));
            queryGenConfigPanel.add(
                    splitQueryLabel, LayoutHelper.getGBC(0, ++i, 1, 1.0, new Insets(2, 2, 2, 2)));
            queryGenConfigPanel.add(
                    getQuerySplitOptions(),
                    LayoutHelper.getGBC(1, i, 1, 1.0, new Insets(2, 2, 2, 2)));
            queryGenConfigPanel.add(
                    requestMethodLabel,
                    LayoutHelper.getGBC(0, ++i, 1, 1.0, new Insets(2, 2, 2, 2)));
            queryGenConfigPanel.add(
                    getRequestMethodOptions(),
                    LayoutHelper.getGBC(1, i, 1, 1.0, new Insets(2, 2, 2, 2)));
        }
        return queryGenConfigPanel;
    }

    private JPanel getCycleDetectionConfigPanel() {
        if (cycleDetectionConfigPanel == null) {
            cycleDetectionConfigPanel = new JPanel(new GridBagLayout());
            cycleDetectionConfigPanel.setBorder(
                    new TitledBorder(
                            Constant.messages.getString(
                                    "graphql.options.cycleDetectionConfigPanel.title")));
            JLabel modeLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "graphql.options.label.cycleDetectionMode"));
            JLabel maxAlertsLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "graphql.options.label.cycleDetectionMaxAlerts"));

            int y = -1;
            cycleDetectionConfigPanel.add(
                    modeLabel, LayoutHelper.getGBC(0, ++y, 1, 1.0, new Insets(2, 2, 2, 2)));
            cycleDetectionConfigPanel.add(
                    getCycleDetectionModeOptions(),
                    LayoutHelper.getGBC(1, y, 1, 1.0, new Insets(2, 2, 2, 2)));
            cycleDetectionConfigPanel.add(
                    maxAlertsLabel, LayoutHelper.getGBC(0, ++y, 1, 1.0, new Insets(2, 2, 2, 2)));
            cycleDetectionConfigPanel.add(
                    getMaxCycleDetectionAlertsNumberSpinner(),
                    LayoutHelper.getGBC(1, y, 1, 1.0, new Insets(2, 2, 2, 2)));
        }
        return cycleDetectionConfigPanel;
    }

    private ZapNumberSpinner getMaxQueryDepthNumberSpinner() {
        if (maxQueryDepthNumberSpinner == null) {
            maxQueryDepthNumberSpinner = new ZapNumberSpinner(0, 0, Integer.MAX_VALUE);
        }
        return maxQueryDepthNumberSpinner;
    }

    private JCheckBox getLenientMaxQueryDepthEnabled() {
        if (lenientMaxQueryDepthEnabled == null) {
            lenientMaxQueryDepthEnabled =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "graphql.options.label.lenientMaxQueryDepthEnabled"));
            lenientMaxQueryDepthEnabled.setToolTipText(
                    Constant.messages.getString(
                            "graphql.options.label.lenientMaxQueryDepthEnabled.tooltip"));
        }
        return lenientMaxQueryDepthEnabled;
    }

    private JLabel getMaxAdditionalQueryDepthLabel() {
        if (maxAdditionalQueryDepthLabel == null) {
            maxAdditionalQueryDepthLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "graphql.options.label.additionalQueryDepth"));
            maxAdditionalQueryDepthLabel.setEnabled(getLenientMaxQueryDepthEnabled().isSelected());
        }
        return maxAdditionalQueryDepthLabel;
    }

    private ZapNumberSpinner getMaxAdditionalQueryDepthNumberSpinner() {
        if (maxAdditionalQueryDepthNumberSpinner == null) {
            maxAdditionalQueryDepthNumberSpinner = new ZapNumberSpinner(0, 0, Integer.MAX_VALUE);
            maxAdditionalQueryDepthNumberSpinner.setEditable(
                    getLenientMaxQueryDepthEnabled().isSelected());
        }
        return maxAdditionalQueryDepthNumberSpinner;
    }

    private ZapNumberSpinner getMaxArgsDepthNumberSpinner() {
        if (maxArgsDepthNumberSpinner == null) {
            maxArgsDepthNumberSpinner = new ZapNumberSpinner(0, 0, Integer.MAX_VALUE);
        }
        return maxArgsDepthNumberSpinner;
    }

    private JCheckBox getOptionalArgsEnabled() {
        if (optionalArgsEnabled == null) {
            optionalArgsEnabled =
                    new JCheckBox(
                            Constant.messages.getString(
                                    "graphql.options.label.optionalArgsEnabled"));
        }
        return optionalArgsEnabled;
    }

    @SuppressWarnings("unchecked")
    private JComboBox<ArgsTypeOption> getArgsTypeOptions() {
        if (argsTypeOptions == null) {
            argsTypeOptions =
                    new JComboBox<>(
                            new ArgsTypeOption[] {
                                ArgsTypeOption.INLINE, ArgsTypeOption.VARIABLES, ArgsTypeOption.BOTH
                            });
        }
        return argsTypeOptions;
    }

    @SuppressWarnings("unchecked")
    private JComboBox<QuerySplitOption> getQuerySplitOptions() {
        if (querySplitOptions == null) {
            querySplitOptions =
                    new JComboBox<>(
                            new QuerySplitOption[] {
                                QuerySplitOption.LEAF,
                                QuerySplitOption.ROOT_FIELD,
                                QuerySplitOption.OPERATION
                            });
        }
        return querySplitOptions;
    }

    private JComboBox<RequestMethodOption> getRequestMethodOptions() {
        if (requestMethodOptions == null) {
            requestMethodOptions =
                    new JComboBox<>(
                            new RequestMethodOption[] {
                                RequestMethodOption.POST_JSON,
                                RequestMethodOption.POST_GRAPHQL,
                                RequestMethodOption.GET
                            });
        }
        return requestMethodOptions;
    }

    private JComboBox<CycleDetectionModeOption> getCycleDetectionModeOptions() {
        if (cycleDetectionModeOptions == null) {
            cycleDetectionModeOptions =
                    new JComboBox<>(
                            new CycleDetectionModeOption[] {
                                CycleDetectionModeOption.DISABLED,
                                CycleDetectionModeOption.QUICK,
                                CycleDetectionModeOption.EXHAUSTIVE
                            });
        }
        return cycleDetectionModeOptions;
    }

    private ZapNumberSpinner getMaxCycleDetectionAlertsNumberSpinner() {
        if (maxCycleDetectionAlertsNumberSpinner == null) {
            maxCycleDetectionAlertsNumberSpinner =
                    new ZapNumberSpinner(
                            0, GraphQlParam.DEFAULT_MAX_CYCLE_DETECTION_ALERTS, Integer.MAX_VALUE);
        }
        return maxCycleDetectionAlertsNumberSpinner;
    }

    @Override
    public String getHelpIndex() {
        return "graphql.options";
    }
}
