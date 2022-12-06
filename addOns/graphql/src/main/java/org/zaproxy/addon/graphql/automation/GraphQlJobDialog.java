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
package org.zaproxy.addon.graphql.automation;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.util.Arrays;
import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JTextField;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.graphql.GraphQlParam;
import org.zaproxy.addon.graphql.automation.GraphQlJob.Parameters;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class GraphQlJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "graphql.automation.dialog.tab.params", "graphql.automation.dialog.tab.adv"
    };

    private static final String TITLE = "graphql.automation.dialog.title";
    private static final String NAME_PARAM = "graphql.automation.dialog.name";
    private static final String ENDPOINT_PARAM = "graphql.automation.dialog.endpoint";
    private static final String SCHEMA_URL_PARAM = "graphql.automation.dialog.schemaurl";
    private static final String SCHEMA_FILE_PARAM = "graphql.automation.dialog.schemafile";
    private static final String FIELD_ADVANCED = "graphql.automation.dialog.advanced";

    private static final String MAX_QUERY_DEPTH_PARAM = "graphql.automation.dialog.maxquerydepth";
    private static final String LENIENT_MAX_QUERY_DEPTH_PARAM =
            "graphql.automation.dialog.lenientmaxquery";
    private static final String MAX_ADD_QUERY_DEPTH_PARAM =
            "graphql.automation.dialog.maxaddquerydepth";
    private static final String MAX_ARGS_DEPTH_PARAM = "graphql.automation.dialog.maxargsdepth";
    private static final String OPTIONAL_ARGS_ENABLED_PARAM =
            "graphql.automation.dialog.optargsenabled";
    private static final String ARGS_TYPE_PARAM = "graphql.automation.dialog.argstype";
    private static final String QUERY_SPLIT_TYPE_PARAM = "graphql.automation.dialog.querysplittype";
    private static final String REQUEST_METHOD_PARAM = "graphql.automation.dialog.requestmethod";

    private static final String VARIABLE_TOKEN = "${";

    private GraphQlJob job;

    private DefaultComboBoxModel<GraphQlParam.ArgsTypeOption> argsTypeModel;
    private DefaultComboBoxModel<GraphQlParam.QuerySplitOption> querySplitModel;
    private DefaultComboBoxModel<GraphQlParam.RequestMethodOption> requestMethodModel;

    public GraphQlJobDialog(GraphQlJob job) {
        super(
                View.getSingleton().getMainFrame(),
                TITLE,
                DisplayUtils.getScaledDimension(500, 400),
                TAB_LABELS);
        this.job = job;

        this.addTextField(0, NAME_PARAM, this.job.getData().getName());
        // Cannot select the node as it might not be present in the Sites tree
        this.addNodeSelectField(0, ENDPOINT_PARAM, null, true, false);
        Component endpointField = this.getField(ENDPOINT_PARAM);
        if (endpointField instanceof JTextField) {
            ((JTextField) endpointField).setText(this.job.getParameters().getEndpoint());
        }
        // Cannot select the node as it might not be present in the Sites tree
        this.addNodeSelectField(0, SCHEMA_URL_PARAM, null, true, false);
        Component schemaUrlField = this.getField(SCHEMA_URL_PARAM);
        if (schemaUrlField instanceof JTextField) {
            ((JTextField) schemaUrlField).setText(this.job.getParameters().getSchemaUrl());
        }
        String fileName = this.job.getData().getParameters().getSchemaFile();
        File f = null;
        if (fileName != null && !fileName.isEmpty()) {
            f = new File(fileName);
        }
        this.addFileSelectField(0, SCHEMA_FILE_PARAM, f, JFileChooser.FILES_AND_DIRECTORIES, null);
        if (fileName != null && fileName.contains(VARIABLE_TOKEN)) {
            setFieldValue(SCHEMA_FILE_PARAM, fileName);
        }

        this.addCheckBoxField(0, FIELD_ADVANCED, advOptionsSet());

        this.addFieldListener(
                FIELD_ADVANCED,
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        setAdvancedTabs(getBoolValue(FIELD_ADVANCED));
                    }
                });

        this.addPadding(0);

        this.addNumberField(
                1,
                MAX_QUERY_DEPTH_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(this.job.getParameters().getMaxQueryDepth()));
        this.addCheckBoxField(
                1,
                LENIENT_MAX_QUERY_DEPTH_PARAM,
                JobUtils.unBox(this.job.getParameters().getLenientMaxQueryDepthEnabled()));
        this.addNumberField(
                1,
                MAX_ADD_QUERY_DEPTH_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(this.job.getParameters().getMaxAdditionalQueryDepth()));
        this.addNumberField(
                1,
                MAX_ARGS_DEPTH_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(this.job.getParameters().getMaxArgsDepth()));
        this.addCheckBoxField(
                1,
                OPTIONAL_ARGS_ENABLED_PARAM,
                JobUtils.unBox(this.job.getParameters().getOptionalArgsEnabled()));

        argsTypeModel = new DefaultComboBoxModel<GraphQlParam.ArgsTypeOption>();
        Arrays.stream(GraphQlParam.ArgsTypeOption.values())
                .forEach(v -> argsTypeModel.addElement(v));
        DefaultListCellRenderer argsTypeRenderer =
                new DefaultListCellRenderer() {
                    private static final long serialVersionUID = 1L;

                    @Override
                    public Component getListCellRendererComponent(
                            JList<?> list,
                            Object value,
                            int index,
                            boolean isSelected,
                            boolean cellHasFocus) {
                        JLabel label =
                                (JLabel)
                                        super.getListCellRendererComponent(
                                                list, value, index, isSelected, cellHasFocus);
                        if (value instanceof GraphQlParam.ArgsTypeOption) {
                            // The name is i18n'ed
                            label.setText(((GraphQlParam.ArgsTypeOption) value).getName());
                        }
                        return label;
                    }
                };

        GraphQlParam.ArgsTypeOption hpo = null;
        if (this.job.getParameters().getArgsType() != null) {
            hpo =
                    GraphQlParam.ArgsTypeOption.valueOf(
                            this.job.getParameters().getArgsType().toUpperCase());
        } else {
            hpo = GraphQlParam.ArgsTypeOption.BOTH;
        }
        argsTypeModel.setSelectedItem(hpo);
        this.addComboField(1, ARGS_TYPE_PARAM, argsTypeModel);
        Component acField = this.getField(ARGS_TYPE_PARAM);
        if (acField instanceof JComboBox) {
            ((JComboBox<?>) acField).setRenderer(argsTypeRenderer);
        }

        querySplitModel = new DefaultComboBoxModel<GraphQlParam.QuerySplitOption>();
        Arrays.stream(GraphQlParam.QuerySplitOption.values())
                .forEach(v -> querySplitModel.addElement(v));
        DefaultListCellRenderer querySplitRenderer =
                new DefaultListCellRenderer() {
                    private static final long serialVersionUID = 1L;

                    @Override
                    public Component getListCellRendererComponent(
                            JList<?> list,
                            Object value,
                            int index,
                            boolean isSelected,
                            boolean cellHasFocus) {
                        JLabel label =
                                (JLabel)
                                        super.getListCellRendererComponent(
                                                list, value, index, isSelected, cellHasFocus);
                        if (value instanceof GraphQlParam.QuerySplitOption) {
                            // The name is i18n'ed
                            label.setText(((GraphQlParam.QuerySplitOption) value).getName());
                        }
                        return label;
                    }
                };

        GraphQlParam.QuerySplitOption qso = null;
        if (this.job.getParameters().getQuerySplitType() != null) {
            qso =
                    GraphQlParam.QuerySplitOption.valueOf(
                            this.job.getParameters().getQuerySplitType().toUpperCase());
        } else {
            qso = GraphQlParam.QuerySplitOption.LEAF;
        }
        querySplitModel.setSelectedItem(qso);
        this.addComboField(1, QUERY_SPLIT_TYPE_PARAM, querySplitModel);
        Component qsField = this.getField(QUERY_SPLIT_TYPE_PARAM);
        if (acField instanceof JComboBox) {
            ((JComboBox<?>) qsField).setRenderer(querySplitRenderer);
        }

        requestMethodModel = new DefaultComboBoxModel<GraphQlParam.RequestMethodOption>();
        Arrays.stream(GraphQlParam.RequestMethodOption.values())
                .forEach(v -> requestMethodModel.addElement(v));
        DefaultListCellRenderer requestMethodRenderer =
                new DefaultListCellRenderer() {
                    private static final long serialVersionUID = 1L;

                    @Override
                    public Component getListCellRendererComponent(
                            JList<?> list,
                            Object value,
                            int index,
                            boolean isSelected,
                            boolean cellHasFocus) {
                        JLabel label =
                                (JLabel)
                                        super.getListCellRendererComponent(
                                                list, value, index, isSelected, cellHasFocus);
                        if (value instanceof GraphQlParam.RequestMethodOption) {
                            // The name is i18n'ed
                            label.setText(((GraphQlParam.RequestMethodOption) value).getName());
                        }
                        return label;
                    }
                };

        GraphQlParam.RequestMethodOption rmo = null;
        if (this.job.getParameters().getRequestMethod() != null) {
            rmo =
                    GraphQlParam.RequestMethodOption.valueOf(
                            this.job.getParameters().getRequestMethod().toUpperCase());
        } else {
            rmo = GraphQlParam.RequestMethodOption.POST_JSON;
        }
        requestMethodModel.setSelectedItem(rmo);
        this.addComboField(1, REQUEST_METHOD_PARAM, requestMethodModel);
        Component rmField = this.getField(REQUEST_METHOD_PARAM);
        if (acField instanceof JComboBox) {
            ((JComboBox<?>) rmField).setRenderer(requestMethodRenderer);
        }
        this.addPadding(1);

        setAdvancedTabs(getBoolValue(FIELD_ADVANCED));
    }

    private boolean advOptionsSet() {
        Parameters params = this.job.getParameters();
        return params.getMaxAdditionalQueryDepth() != null
                || params.getLenientMaxQueryDepthEnabled() != null
                || params.getMaxAdditionalQueryDepth() != null
                || params.getMaxArgsDepth() != null
                || params.getOptionalArgsEnabled() != null
                || !StringUtils.isEmpty(params.getQuerySplitType())
                || !StringUtils.isEmpty(params.getRequestMethod());
    }

    private void setAdvancedTabs(boolean visible) {
        // Show/hide all except from the first tab
        this.setTabsVisible(new String[] {"graphql.automation.dialog.tab.adv"}, visible);
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getParameters().setEndpoint(this.getStringValue(ENDPOINT_PARAM));
        this.job.getParameters().setSchemaUrl(this.getStringValue(SCHEMA_URL_PARAM));
        this.job.getParameters().setSchemaFile(this.getStringValue(SCHEMA_FILE_PARAM));

        if (this.getBoolValue(FIELD_ADVANCED)) {
            this.job.getParameters().setMaxQueryDepth(this.getIntValue(MAX_QUERY_DEPTH_PARAM));
            this.job
                    .getParameters()
                    .setLenientMaxQueryDepthEnabled(
                            this.getBoolValue(LENIENT_MAX_QUERY_DEPTH_PARAM));
            this.job
                    .getParameters()
                    .setMaxAdditionalQueryDepth(this.getIntValue(MAX_ADD_QUERY_DEPTH_PARAM));
            this.job.getParameters().setMaxArgsDepth(this.getIntValue(MAX_ARGS_DEPTH_PARAM));
            this.job
                    .getParameters()
                    .setOptionalArgsEnabled(this.getBoolValue(OPTIONAL_ARGS_ENABLED_PARAM));

            Object atObj = argsTypeModel.getSelectedItem();
            if (atObj instanceof GraphQlParam.ArgsTypeOption) {
                GraphQlParam.ArgsTypeOption at = (GraphQlParam.ArgsTypeOption) atObj;
                this.job.getParameters().setArgsType(at.name().toLowerCase());
            }
            Object sqObj = querySplitModel.getSelectedItem();
            if (sqObj instanceof GraphQlParam.QuerySplitOption) {
                GraphQlParam.QuerySplitOption sq = (GraphQlParam.QuerySplitOption) sqObj;
                this.job.getParameters().setQuerySplitType(sq.name().toLowerCase());
            }

            Object rmObj = requestMethodModel.getSelectedItem();
            if (rmObj instanceof GraphQlParam.RequestMethodOption) {
                GraphQlParam.RequestMethodOption rm = (GraphQlParam.RequestMethodOption) rmObj;
                this.job.getParameters().setRequestMethod(rm.name().toLowerCase());
            }

        } else {
            this.job.getParameters().setMaxQueryDepth(null);
            this.job.getParameters().setLenientMaxQueryDepthEnabled(null);
            this.job.getParameters().setMaxAdditionalQueryDepth(null);
            this.job.getParameters().setMaxArgsDepth(null);
            this.job.getParameters().setOptionalArgsEnabled(null);
            this.job.getParameters().setArgsType(null);
            this.job.getParameters().setQuerySplitType(null);
            this.job.getParameters().setRequestMethod(null);
        }
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }
}
