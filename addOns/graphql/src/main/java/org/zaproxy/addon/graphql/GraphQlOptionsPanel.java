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

import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.plaf.basic.BasicComboBoxRenderer;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.addon.graphql.GraphQlParam.ArgsTypeOption;
import org.zaproxy.addon.graphql.GraphQlParam.QuerySplitOption;
import org.zaproxy.addon.graphql.GraphQlParam.RequestMethodOption;
import org.zaproxy.zap.utils.ZapNumberSpinner;
import org.zaproxy.zap.view.LayoutHelper;

/** The GraphQL options panel. */
public class GraphQlOptionsPanel extends AbstractParamPanel {

    private static final long serialVersionUID = 1L;

    /** The name of the options panel. */
    private static final String NAME = Constant.messages.getString("graphql.options.panelName");

    private ZapNumberSpinner maxQueryDepthNumberSpinner;
    private ZapNumberSpinner maxArgsDepthNumberSpinner;
    private JCheckBox optionalArgsEnabled = null;
    private JComboBox<ArgsTypeOption> argsTypeOptions = null;
    private JComboBox<QuerySplitOption> querySplitOptions = null;
    private JComboBox<RequestMethodOption> requestMethodOptions = null;

    public GraphQlOptionsPanel() {
        super();
        setName(NAME);

        setLayout(new FlowLayout(FlowLayout.LEADING, 0, 0));

        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(2, 2, 2, 2));

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

        int i = 0;
        panel.add(maxQueryDepthLabel, LayoutHelper.getGBC(0, ++i, 1, 1.0, new Insets(2, 2, 2, 2)));
        panel.add(
                getMaxQueryDepthNumberSpinner(),
                LayoutHelper.getGBC(1, i, 1, 1.0, new Insets(2, 2, 2, 2)));
        panel.add(maxArgsDepthLabel, LayoutHelper.getGBC(0, ++i, 1, 1.0, new Insets(2, 2, 2, 2)));
        panel.add(
                getMaxArgsDepthNumberSpinner(),
                LayoutHelper.getGBC(1, i, 1, 1.0, new Insets(2, 2, 2, 2)));
        panel.add(
                getOptionalArgsEnabled(),
                LayoutHelper.getGBC(0, ++i, 2, 1.0, new Insets(2, 2, 2, 2)));
        panel.add(argsTypeLabel, LayoutHelper.getGBC(0, ++i, 1, 1.0, new Insets(2, 2, 2, 2)));
        panel.add(getArgsTypeOptions(), LayoutHelper.getGBC(1, i, 1, 1.0, new Insets(2, 2, 2, 2)));
        panel.add(splitQueryLabel, LayoutHelper.getGBC(0, ++i, 1, 1.0, new Insets(2, 2, 2, 2)));
        panel.add(
                getQuerySplitOptions(), LayoutHelper.getGBC(1, i, 1, 1.0, new Insets(2, 2, 2, 2)));
        panel.add(requestMethodLabel, LayoutHelper.getGBC(0, ++i, 1, 1.0, new Insets(2, 2, 2, 2)));
        panel.add(
                getRequestMethodOptions(),
                LayoutHelper.getGBC(1, i, 1, 1.0, new Insets(2, 2, 2, 2)));

        add(panel);
    }

    @Override
    public void initParam(Object obj) {
        final OptionsParam options = (OptionsParam) obj;
        final GraphQlParam param = options.getParamSet(GraphQlParam.class);

        getMaxQueryDepthNumberSpinner().setValue(param.getMaxQueryDepth());
        getMaxArgsDepthNumberSpinner().setValue(param.getMaxArgsDepth());
        getOptionalArgsEnabled().setSelected(param.getOptionalArgsEnabled());
        getArgsTypeOptions().setSelectedItem(param.getArgsType());
        getQuerySplitOptions().setSelectedItem(param.getQuerySplitType());
        getRequestMethodOptions().setSelectedItem(param.getRequestMethod());
    }

    @Override
    public void saveParam(Object obj) throws Exception {
        final OptionsParam options = (OptionsParam) obj;
        final GraphQlParam param = options.getParamSet(GraphQlParam.class);

        param.setMaxQueryDepth(getMaxQueryDepthNumberSpinner().getValue());
        param.setMaxArgsDepth(getMaxArgsDepthNumberSpinner().getValue());
        param.setOptionalArgsEnabled(getOptionalArgsEnabled().isSelected());
        param.setArgsType((ArgsTypeOption) getArgsTypeOptions().getSelectedItem());
        param.setQuerySplitType((QuerySplitOption) getQuerySplitOptions().getSelectedItem());
        param.setRequestMethod((RequestMethodOption) getRequestMethodOptions().getSelectedItem());
    }

    private ZapNumberSpinner getMaxQueryDepthNumberSpinner() {
        if (maxQueryDepthNumberSpinner == null) {
            maxQueryDepthNumberSpinner = new ZapNumberSpinner(0, 0, Integer.MAX_VALUE);
        }
        return maxQueryDepthNumberSpinner;
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
                    new JComboBox<ArgsTypeOption>(
                            new ArgsTypeOption[] {
                                ArgsTypeOption.INLINE, ArgsTypeOption.VARIABLES, ArgsTypeOption.BOTH
                            });
            argsTypeOptions.setRenderer(new CustomComboBoxRenderer());
        }
        return argsTypeOptions;
    }

    @SuppressWarnings("unchecked")
    private JComboBox<QuerySplitOption> getQuerySplitOptions() {
        if (querySplitOptions == null) {
            querySplitOptions =
                    new JComboBox<QuerySplitOption>(
                            new QuerySplitOption[] {
                                QuerySplitOption.LEAF,
                                QuerySplitOption.ROOT_FIELD,
                                QuerySplitOption.OPERATION
                            });
            querySplitOptions.setRenderer(new CustomComboBoxRenderer());
        }
        return querySplitOptions;
    }

    @SuppressWarnings("unchecked")
    private JComboBox<RequestMethodOption> getRequestMethodOptions() {
        if (requestMethodOptions == null) {
            requestMethodOptions =
                    new JComboBox<RequestMethodOption>(
                            new RequestMethodOption[] {
                                RequestMethodOption.POST_JSON,
                                RequestMethodOption.POST_GRAPHQL,
                                RequestMethodOption.GET
                            });
            requestMethodOptions.setRenderer(new CustomComboBoxRenderer());
        }
        return requestMethodOptions;
    }

    @Override
    public String getHelpIndex() {
        return "graphql.options";
    }

    /** A renderer for properly displaying the name of options in a ComboBox. */
    private static class CustomComboBoxRenderer extends BasicComboBoxRenderer {
        private static final long serialVersionUID = 1L;
        private static final Border BORDER = new EmptyBorder(2, 3, 3, 3);

        @Override
        @SuppressWarnings("rawtypes")
        public Component getListCellRendererComponent(
                JList list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            if (value != null) {
                setBorder(BORDER);
                if (value instanceof ArgsTypeOption) {
                    ArgsTypeOption item = (ArgsTypeOption) value;
                    setText(item.getName());
                } else if (value instanceof QuerySplitOption) {
                    QuerySplitOption item = (QuerySplitOption) value;
                    setText(item.getName());
                } else if (value instanceof RequestMethodOption) {
                    RequestMethodOption item = (RequestMethodOption) value;
                    setText(item.getName());
                }
            }
            return this;
        }
    }
}
