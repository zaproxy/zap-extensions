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
package org.zaproxy.addon.automation.gui;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JTable;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.automation.jobs.ApiJob;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiElement;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

public class ApiJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "automation.dialog.api.title";
    private static final String NAME_PARAM = "automation.dialog.all.name";
    private static final String API_KEY_PARAM = "automation.dialog.api.apiKey";
    private static final String API_NAME_PARAM = "automation.dialog.api.apiName";
    private static final String API_PREFIX_PARAM = "automation.dialog.api.apiPrefix";
    private static final String API_REQUEST_TYPE_PARAM = "automation.dialog.api.apiRequestType";
    private static final String OUTPUT_FORMAT_PARAM = "automation.dialog.api.outputFormat";

    private static final String[] TAB_LABELS = {
        "automation.dialog.tab.params", "automation.dialog.api.tab.apiParameters"
    };

    private JTable apiParametersTable = null;
    private ApiParameterTableModel apiParametersModel = null;

    private JButton addButton = null;
    private JButton modifyButton = null;
    private JButton removeButton = null;

    private ApiJob job;

    public ApiJobDialog(ApiJob job) {
        super(
                View.getSingleton().getMainFrame(),
                TITLE,
                DisplayUtils.getScaledDimension(500, 300),
                TAB_LABELS);
        this.job = job;

        this.addTextField(0, NAME_PARAM, this.job.getData().getName());
        this.addTextField(0, API_KEY_PARAM, this.job.getData().getParameters().getApiKey());
        this.addComboField(
                0,
                API_PREFIX_PARAM,
                getPossibleApiPrefixes(),
                this.job.getData().getParameters().getApiPrefix(),
                false);
        this.addFieldListener(API_PREFIX_PARAM, e -> onApiPrefixOrRequestTypeChanged());
        this.addComboField(
                0,
                API_REQUEST_TYPE_PARAM,
                getPossibleApiRequestTypes(),
                this.job.getData().getParameters().getApiRequestType(),
                false);
        this.addFieldListener(API_REQUEST_TYPE_PARAM, e -> onApiPrefixOrRequestTypeChanged());
        this.addComboField(
                0,
                API_NAME_PARAM,
                new ArrayList<>(),
                this.job.getData().getParameters().getApiName(),
                false);
        this.addFieldListener(API_NAME_PARAM, e -> onApiNameChanged());
        this.addComboField(
                0,
                OUTPUT_FORMAT_PARAM,
                getPossibleApiOutputFormats(),
                this.job.getData().getParameters().getApiOutputFormat(),
                false);

        this.addPadding(0);

        List<JButton> buttons = new ArrayList<>();
        buttons.add(getAddButton());
        buttons.add(getModifyButton());
        buttons.add(getRemoveButton());

        this.addTableField(1, getApiParameterTable(), buttons);

        onApiPrefixOrRequestTypeChanged();
        onApiNameChanged();
    }

    private static List<String> getPossibleApiOutputFormats() {
        return EnumSet.allOf(API.Format.class).stream()
                .map(e -> e.name())
                .collect(Collectors.toList());
    }

    private static List<String> getPossibleApiRequestTypes() {
        return EnumSet.allOf(API.RequestType.class).stream()
                .map(e -> e.name())
                .collect(Collectors.toList());
    }

    private static String[] getPossibleApiPrefixes() {
        return API.getInstance().getImplementors().keySet().toArray(new String[] {});
    }

    private void onApiPrefixOrRequestTypeChanged() {
        List<String> apiNames =
                getPossibleApiElements().stream()
                        .map(e -> e.getName())
                        .collect(Collectors.toList());
        this.setComboFields(
                API_NAME_PARAM, apiNames, this.job.getData().getParameters().getApiName());
    }

    private List<ApiElement> getPossibleApiElements() {
        String prefix = getStringValue(API_PREFIX_PARAM);

        if (StringUtils.isEmpty(prefix)) {
            return new ArrayList<>();
        }

        ApiImplementor apiImplementor = API.getInstance().getImplementors().get(prefix);
        if (apiImplementor == null) {
            return new ArrayList<>();
        }

        API.RequestType requestType =
                API.RequestType.valueOf(getStringValue(API_REQUEST_TYPE_PARAM));
        if (requestType == null) {
            return new ArrayList<>();
        }

        return getPossibleApiElements(apiImplementor, requestType);
    }

    private void onApiNameChanged() {
        List<ApiJob.ApiParameter> apiParameters = new ArrayList<>();
        for (String possibleApiParameters : getPossibleApiParameters()) {
            Optional<ApiJob.ApiParameter> existingApiParameter =
                    this.job.getData().getApiParameters().stream()
                            .filter(p -> Objects.equals(p.getName(), possibleApiParameters))
                            .findFirst();
            String value = "";
            if (existingApiParameter.isPresent()) {
                value = existingApiParameter.get().getValue();
            }
            apiParameters.add(new ApiJob.ApiParameter(possibleApiParameters, value));
        }
        this.getApiParameterTableModel().setApiParameters(apiParameters);
    }

    private List<String> getPossibleApiParameters() {
        List<ApiElement> apiElements = getPossibleApiElements();
        String name = getStringValue(API_NAME_PARAM);

        if (StringUtils.isEmpty(name)) {
            return new ArrayList<>();
        }
        Optional<ApiElement> apiElement =
                apiElements.stream().filter(e -> Objects.equals(e.getName(), name)).findFirst();
        if (!apiElement.isPresent()) {
            return new ArrayList<>();
        }

        return apiElement.get().getParameters().stream()
                .map(p -> p.getName())
                .collect(Collectors.toList());
    }

    private List<ApiElement> getPossibleApiElements(
            ApiImplementor apiImplementor, API.RequestType requestType) {
        List<ApiElement> apiElements = new ArrayList<>();
        switch (requestType) {
            case action:
                apiElements = apiImplementor.getApiActions().stream().collect(Collectors.toList());
                break;
            case view:
                apiElements = apiImplementor.getApiViews().stream().collect(Collectors.toList());
                break;
            case other:
                apiElements = apiImplementor.getApiOthers().stream().collect(Collectors.toList());
                break;
            case pconn:
                apiElements =
                        apiImplementor.getApiPersistentConnections().stream()
                                .collect(Collectors.toList());
                break;
        }
        return apiElements;
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getData().setApiParameters(this.getApiParameterTableModel().getApiParameters());

        this.job.getParameters().setApiPrefix(this.getStringValue(API_PREFIX_PARAM));
        this.job.getParameters().setApiKey(this.getStringValue(API_KEY_PARAM));
        this.job.getParameters().setApiRequestType(this.getStringValue(API_REQUEST_TYPE_PARAM));
        this.job.getParameters().setApiName(this.getStringValue(API_NAME_PARAM));
        this.job.getParameters().setApiOutputFormat(this.getStringValue(OUTPUT_FORMAT_PARAM));
        this.job.setChanged();
        this.job.reset();
        this.job.setJobData(new LinkedHashMap<>());
    }

    @Override
    public String validateFields() {
        return null;
    }

    private JButton getAddButton() {
        if (this.addButton == null) {
            this.addButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.add"));
            this.addButton.addActionListener(
                    e -> {
                        AddApiParameterDialog dialog =
                                new AddApiParameterDialog(getApiParameterTableModel());
                        dialog.setVisible(true);
                    });
        }
        return this.addButton;
    }

    private JButton getModifyButton() {
        if (this.modifyButton == null) {
            this.modifyButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.modify"));
            this.modifyButton.addActionListener(
                    e -> {
                        int row = getApiParameterTable().getSelectedRow();
                        AddApiParameterDialog dialog =
                                new AddApiParameterDialog(
                                        getApiParameterTableModel(),
                                        getApiParameterTableModel().getApiParameters().get(row),
                                        row);
                        dialog.setVisible(true);
                    });
        }
        return this.modifyButton;
    }

    private JButton getRemoveButton() {
        if (this.removeButton == null) {
            this.removeButton =
                    new JButton(Constant.messages.getString("automation.dialog.button.remove"));
            this.removeButton.setEnabled(false);
            final ApiJobDialog parent = this;
            this.removeButton.addActionListener(
                    e -> {
                        if (JOptionPane.OK_OPTION
                                == View.getSingleton()
                                        .showConfirmDialog(
                                                parent,
                                                Constant.messages.getString(
                                                        "automation.dialog.pscanconfig.remove.confirm"))) {
                            getApiParameterTableModel()
                                    .remove(getApiParameterTable().getSelectedRow());
                        }
                    });
        }
        return this.removeButton;
    }

    private JTable getApiParameterTable() {
        if (apiParametersTable == null) {
            apiParametersTable = new JTable();
            apiParametersTable.setModel(getApiParameterTableModel());
            apiParametersTable
                    .getColumnModel()
                    .getColumn(0)
                    .setPreferredWidth(DisplayUtils.getScaledSize(100));
            apiParametersTable
                    .getColumnModel()
                    .getColumn(1)
                    .setPreferredWidth(DisplayUtils.getScaledSize(290));
            apiParametersTable
                    .getSelectionModel()
                    .addListSelectionListener(
                            e -> {
                                boolean singleRowSelected =
                                        getApiParameterTable().getSelectedRowCount() == 1;
                                modifyButton.setEnabled(singleRowSelected);
                                removeButton.setEnabled(singleRowSelected);
                            });
            apiParametersTable.addMouseListener(
                    new MouseAdapter() {
                        @Override
                        public void mouseClicked(MouseEvent me) {
                            if (me.getClickCount() == 2) {
                                int row = getApiParameterTable().getSelectedRow();
                                AddApiParameterDialog dialog =
                                        new AddApiParameterDialog(
                                                getApiParameterTableModel(),
                                                getApiParameterTableModel()
                                                        .getApiParameters()
                                                        .get(row),
                                                row);
                                dialog.setVisible(true);
                            }
                        }
                    });
        }
        return apiParametersTable;
    }

    private ApiParameterTableModel getApiParameterTableModel() {
        if (apiParametersModel == null) {
            apiParametersModel = new ApiParameterTableModel();
            apiParametersModel.setApiParameters(job.getData().getApiParameters());
        }
        return apiParametersModel;
    }
}
