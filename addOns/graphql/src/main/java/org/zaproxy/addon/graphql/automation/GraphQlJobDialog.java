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
import java.io.File;
import java.util.Arrays;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JFileChooser;
import javax.swing.JTextField;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.graphql.GraphQlParam;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class GraphQlJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String[] TAB_LABELS = {
        "graphql.automation.dialog.tab.params",
        "graphql.automation.dialog.tab.queryGenConfig",
        "graphql.automation.dialog.tab.cycleDetectionConfig"
    };

    private static final String TITLE = "graphql.automation.dialog.title";
    private static final String NAME_PARAM = "graphql.automation.dialog.name";
    private static final String ENDPOINT_PARAM = "graphql.automation.dialog.endpoint";
    private static final String SCHEMA_URL_PARAM = "graphql.automation.dialog.schemaurl";
    private static final String SCHEMA_FILE_PARAM = "graphql.automation.dialog.schemafile";

    private static final String QUERY_GEN_ENABLED_PARAM = "graphql.automation.dialog.querygen";
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
    private static final String CYCLE_DETECTION_MODE_PARAM =
            "graphql.automation.dialog.cycleDetectionMode";
    private static final String MAX_CYCLE_DETECTION_ALERTS_PARAM =
            "graphql.automation.dialog.maxCycleAlerts";

    private GraphQlJob job;

    private DefaultComboBoxModel<GraphQlParam.ArgsTypeOption> argsTypeModel;
    private DefaultComboBoxModel<GraphQlParam.QuerySplitOption> querySplitModel;
    private DefaultComboBoxModel<GraphQlParam.RequestMethodOption> requestMethodModel;
    private DefaultComboBoxModel<GraphQlParam.CycleDetectionModeOption> cycleDetectionModel;

    public GraphQlJobDialog(GraphQlJob job) {
        super(
                View.getSingleton().getMainFrame(),
                TITLE,
                DisplayUtils.getScaledDimension(500, 400),
                TAB_LABELS);
        this.job = job;

        /* Parameters Tab */
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
        if (fileName != null && JobUtils.containsVars(fileName)) {
            setFieldValue(SCHEMA_FILE_PARAM, fileName);
        }

        this.addCheckBoxField(
                0,
                QUERY_GEN_ENABLED_PARAM,
                JobUtils.unBox(this.job.getParameters().getQueryGenEnabled()));
        this.addPadding(0);

        /* Query Generator Config Tab */
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

        argsTypeModel = new DefaultComboBoxModel<>();
        Arrays.stream(GraphQlParam.ArgsTypeOption.values())
                .forEach(v -> argsTypeModel.addElement(v));
        argsTypeModel.setSelectedItem(
                this.job.getParameters().getArgsType() != null
                        ? GraphQlParam.ArgsTypeOption.valueOf(
                                this.job.getParameters().getArgsType().toUpperCase())
                        : GraphQlParam.ArgsTypeOption.BOTH);
        this.addComboField(1, ARGS_TYPE_PARAM, argsTypeModel);

        querySplitModel = new DefaultComboBoxModel<>();
        Arrays.stream(GraphQlParam.QuerySplitOption.values())
                .forEach(v -> querySplitModel.addElement(v));
        querySplitModel.setSelectedItem(
                this.job.getParameters().getQuerySplitType() != null
                        ? GraphQlParam.QuerySplitOption.valueOf(
                                this.job.getParameters().getQuerySplitType().toUpperCase())
                        : GraphQlParam.QuerySplitOption.LEAF);
        this.addComboField(1, QUERY_SPLIT_TYPE_PARAM, querySplitModel);

        requestMethodModel = new DefaultComboBoxModel<>();
        Arrays.stream(GraphQlParam.RequestMethodOption.values())
                .forEach(v -> requestMethodModel.addElement(v));
        requestMethodModel.setSelectedItem(
                this.job.getParameters().getRequestMethod() != null
                        ? GraphQlParam.RequestMethodOption.valueOf(
                                this.job.getParameters().getRequestMethod().toUpperCase())
                        : GraphQlParam.RequestMethodOption.POST_JSON);
        this.addComboField(1, REQUEST_METHOD_PARAM, requestMethodModel);

        this.addPadding(1);

        /* Cycle Detection Config Tab */
        cycleDetectionModel = new DefaultComboBoxModel<>();
        Arrays.stream(GraphQlParam.CycleDetectionModeOption.values())
                .forEach(cycleDetectionModel::addElement);
        cycleDetectionModel.setSelectedItem(
                this.job.getParameters().getCycleDetectionMode() != null
                        ? GraphQlParam.CycleDetectionModeOption.valueOf(
                                this.job.getParameters().getCycleDetectionMode().toUpperCase())
                        : GraphQlParam.CycleDetectionModeOption.QUICK);
        this.addComboField(2, CYCLE_DETECTION_MODE_PARAM, cycleDetectionModel);

        this.addNumberField(
                2,
                MAX_CYCLE_DETECTION_ALERTS_PARAM,
                0,
                Integer.MAX_VALUE,
                JobUtils.unBox(this.job.getParameters().getMaxCycleDetectionAlerts()));

        this.addPadding(2);
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getParameters().setEndpoint(this.getStringValue(ENDPOINT_PARAM));
        this.job.getParameters().setSchemaUrl(this.getStringValue(SCHEMA_URL_PARAM));
        this.job.getParameters().setSchemaFile(this.getStringValue(SCHEMA_FILE_PARAM));

        boolean queryGenEnabled = getBoolValue(QUERY_GEN_ENABLED_PARAM);
        this.job.getParameters().setQueryGenEnabled(queryGenEnabled);
        if (queryGenEnabled) {
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

            Object cdmObj = cycleDetectionModel.getSelectedItem();
            if (cdmObj instanceof GraphQlParam.CycleDetectionModeOption) {
                GraphQlParam.CycleDetectionModeOption cdm =
                        (GraphQlParam.CycleDetectionModeOption) cdmObj;
                this.job.getParameters().setCycleDetectionMode(cdm.name().toLowerCase());
            }
            this.job
                    .getParameters()
                    .setMaxCycleDetectionAlerts(this.getIntValue(MAX_CYCLE_DETECTION_ALERTS_PARAM));

        } else {
            this.job.getParameters().setMaxQueryDepth(null);
            this.job.getParameters().setLenientMaxQueryDepthEnabled(null);
            this.job.getParameters().setMaxAdditionalQueryDepth(null);
            this.job.getParameters().setMaxArgsDepth(null);
            this.job.getParameters().setOptionalArgsEnabled(null);
            this.job.getParameters().setArgsType(null);
            this.job.getParameters().setQuerySplitType(null);
            this.job.getParameters().setRequestMethod(null);
            this.job.getParameters().setCycleDetectionMode(null);
            this.job.getParameters().setMaxCycleDetectionAlerts(null);
        }
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        // Nothing to do
        return null;
    }
}
