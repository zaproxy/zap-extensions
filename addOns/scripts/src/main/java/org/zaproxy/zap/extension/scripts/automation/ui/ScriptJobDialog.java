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
package org.zaproxy.zap.extension.scripts.automation.ui;

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.JTextComponent;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.scripts.automation.ScriptJob;
import org.zaproxy.zap.extension.scripts.automation.ScriptJobParameters;
import org.zaproxy.zap.extension.scripts.automation.actions.RunScriptAction;
import org.zaproxy.zap.extension.scripts.automation.actions.ScriptAction;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.FontUtils;
import org.zaproxy.zap.utils.ZapHtmlLabel;
import org.zaproxy.zap.utils.ZapTextArea;
import org.zaproxy.zap.view.LayoutHelper;
import org.zaproxy.zap.view.StandardFieldsDialog;

@SuppressWarnings("serial")
public class ScriptJobDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "scripts.automation.dialog.title";
    public static final String NAME_PARAM = "scripts.automation.dialog.name";
    public static final String SCRIPT_ACTION_PARAM = "scripts.automation.dialog.action";
    public static final String SCRIPT_TYPE_PARAM = "scripts.automation.dialog.scriptType";
    public static final String SCRIPT_ENGINE_PARAM = "scripts.automation.dialog.scriptEngine";
    public static final String SCRIPT_NAME_PARAM = "scripts.automation.dialog.scriptName";
    public static final String SCRIPT_FILE_PARAM = "scripts.automation.dialog.scriptFile";
    public static final String SCRIPT_TARGET_PARAM = "scripts.automation.dialog.target";
    public static final String SCRIPT_IS_INLINE_PARAM = "scripts.automation.dialog.isinline";
    public static final String SCRIPT_INLINE_PARAM = "scripts.automation.dialog.inline";
    public static final String SCRIPT_CONTEXT_PARAM = "scripts.automation.dialog.context";
    public static final String SCRIPT_USER_PARAM = "scripts.automation.dialog.user";
    private static final String SCRIPT_USE_CHAIN_LABEL = "scripts.automation.dialog.useChain";
    private static final String SCRIPT_CHAIN_GROUP_LABEL = "scripts.automation.dialog.chain.group";
    private static final String SCRIPT_CHAIN_HELP_LABEL = "scripts.automation.dialog.chain.help";
    private static final String SCRIPT_FILL_CHAIN_LABEL =
            "scripts.automation.dialog.chain.fillFromPlan";

    private static final String[] ALL_FIELDS = {
        NAME_PARAM,
        SCRIPT_ACTION_PARAM,
        SCRIPT_TYPE_PARAM,
        SCRIPT_ENGINE_PARAM,
        SCRIPT_IS_INLINE_PARAM,
        SCRIPT_INLINE_PARAM,
        SCRIPT_NAME_PARAM,
        SCRIPT_FILE_PARAM,
        SCRIPT_TARGET_PARAM,
        SCRIPT_CONTEXT_PARAM,
        SCRIPT_USER_PARAM
    };

    private static final String[] TAB_LABELS = {
        "scripts.automation.dialog.tab.script", "scripts.automation.dialog.tab.inline"
    };

    private ScriptJob job;

    private Map<String, String> lastValues = new HashMap<>();

    private JButton fillChainButton;

    private JPanel chainGroupPanel;

    private JCheckBox useChainCheckBox;

    private ZapTextArea chainTextArea;

    public ScriptJobDialog(ScriptJob job) {
        super(
                View.getSingleton().getMainFrame(),
                TITLE,
                DisplayUtils.getScaledDimension(400, 400),
                TAB_LABELS);
        this.job = job;

        this.addTextField(0, NAME_PARAM, this.job.getData().getName());
        this.addComboField(
                0,
                SCRIPT_ACTION_PARAM,
                ScriptJob.validActions(),
                this.job.getData().getParameters().getAction(),
                false);
        this.addFieldListener(SCRIPT_ACTION_PARAM, e -> onScriptActionChanged());
        this.addComboField(
                0,
                SCRIPT_TYPE_PARAM,
                new ArrayList<>(),
                this.job.getData().getParameters().getType(),
                false);
        this.addFieldListener(SCRIPT_TYPE_PARAM, e -> onScriptTypeChanged());
        List<String> engineList = new ArrayList<>(ScriptAction.getScriptingEngines());
        engineList.add(0, "");
        this.addComboField(
                0,
                SCRIPT_ENGINE_PARAM,
                engineList,
                this.job.getData().getParameters().getEngine(),
                false);
        this.addComboField(
                0,
                SCRIPT_NAME_PARAM,
                new ArrayList<>(),
                this.job.getData().getParameters().getName(),
                true);
        this.addFieldListener(SCRIPT_NAME_PARAM, e -> onScriptNameChanged());

        List<String> contextNames = this.job.getEnv().getContextNames();
        // Add blank option
        contextNames.add(0, "");
        this.addComboField(
                0, SCRIPT_CONTEXT_PARAM, contextNames, this.job.getParameters().getContext());

        List<String> users = job.getEnv().getAllUserNames();
        // Add blank option
        users.add(0, "");
        this.addComboField(
                0, SCRIPT_USER_PARAM, users, this.job.getData().getParameters().getUser());

        boolean isInline = StringUtils.isNotEmpty(this.job.getData().getParameters().getInline());
        this.addCheckBoxField(0, SCRIPT_IS_INLINE_PARAM, isInline);
        this.addFieldListener(SCRIPT_IS_INLINE_PARAM, e -> onIsInlineChanged());

        String fileName = this.job.getData().getParameters().getSource();
        File f;
        if (StringUtils.isEmpty(fileName)) {
            f = getDefaultDirectory();
        } else {
            f = new File(fileName);
        }
        this.addFileSelectField(0, SCRIPT_FILE_PARAM, f, JFileChooser.FILES_AND_DIRECTORIES, null);
        if (isInline) {
            this.setFieldValue(SCRIPT_FILE_PARAM, "");
        }
        // Cannot select the node as it might not be present in the Sites tree
        this.addNodeSelectField(0, SCRIPT_TARGET_PARAM, null, true, false);
        Component scriptTargetField = this.getField(SCRIPT_TARGET_PARAM);
        if (scriptTargetField instanceof JTextField) {
            ((JTextField) scriptTargetField)
                    .setText(this.job.getData().getParameters().getTarget());
        }

        boolean useChainInitially = isChainConfigured(this.job.getData().getParameters());
        addChainGroupPanel(
                useChainInitially,
                ScriptChainPlanSupport.formatChainText(
                        this.job.getData().getParameters().getChain()));

        this.addPadding(0);

        this.addMultilineField(
                1, SCRIPT_INLINE_PARAM, this.job.getData().getParameters().getInline());

        onScriptActionChanged();
        onScriptTypeChanged();
        if (useChainInitially) {
            onUseChainChanged();
        }

        layoutDialog();
    }

    /**
     * Scrollable tabs and {@link #pack()} for final size. Clears the bootstrap preferred size
     * {@link StandardFieldsDialog} sets on the content pane (required by its constructor).
     */
    private void layoutDialog() {
        for (String tabLabel : TAB_LABELS) {
            setTabScrollable(tabLabel, true);
        }

        Component content = getContentPane();
        if (content != null) {
            content.setPreferredSize(null);
            content.setMinimumSize(null);
        }

        setResizable(true);
        pack();
    }

    private static String formatChainHelpHtml(String helpText) {
        return "<html>" + helpText.replace("\n", "<br>") + "</html>";
    }

    private void addChainGroupPanel(boolean useChainInitially, String initialChainText) {
        chainGroupPanel = new JPanel(new GridBagLayout());
        chainGroupPanel.setBorder(
                BorderFactory.createTitledBorder(
                        null,
                        Constant.messages.getString(SCRIPT_CHAIN_GROUP_LABEL),
                        TitledBorder.DEFAULT_JUSTIFICATION,
                        TitledBorder.DEFAULT_POSITION,
                        FontUtils.getFont(FontUtils.Size.standard)));

        useChainCheckBox =
                new JCheckBox(
                        Constant.messages.getString(SCRIPT_USE_CHAIN_LABEL), useChainInitially);
        useChainCheckBox.addActionListener(e -> onUseChainChanged());
        chainGroupPanel.add(
                useChainCheckBox,
                LayoutHelper.getGBC(
                        0, 0, 2, 1.0, 0.0, GridBagConstraints.HORIZONTAL, new Insets(2, 4, 4, 4)));

        chainTextArea = new ZapTextArea();
        chainTextArea.setLineWrap(true);
        chainTextArea.setText(initialChainText);
        chainTextArea
                .getDocument()
                .addDocumentListener(
                        new DocumentListener() {
                            @Override
                            public void insertUpdate(DocumentEvent e) {
                                onChainTextChanged();
                            }

                            @Override
                            public void removeUpdate(DocumentEvent e) {
                                onChainTextChanged();
                            }

                            @Override
                            public void changedUpdate(DocumentEvent e) {
                                onChainTextChanged();
                            }
                        });
        JScrollPane chainScrollPane = new JScrollPane(chainTextArea);
        chainScrollPane.setVerticalScrollBarPolicy(
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        chainGroupPanel.add(
                chainScrollPane,
                LayoutHelper.getGBC(
                        0, 1, 2, 1.0, 1.0, GridBagConstraints.BOTH, new Insets(2, 4, 4, 4)));

        ZapHtmlLabel chainHelpLabel =
                new ZapHtmlLabel(
                        formatChainHelpHtml(Constant.messages.getString(SCRIPT_CHAIN_HELP_LABEL)));
        chainGroupPanel.add(
                chainHelpLabel,
                LayoutHelper.getGBC(
                        0, 2, 2, 1.0, 0.0, GridBagConstraints.HORIZONTAL, new Insets(2, 4, 4, 4)));

        fillChainButton = new JButton(Constant.messages.getString(SCRIPT_FILL_CHAIN_LABEL));
        fillChainButton.addActionListener(e -> fillChainFromPriorAddJobs());
        chainGroupPanel.add(
                fillChainButton,
                LayoutHelper.getGBC(
                        0, 3, 2, 0.0, 0.0, GridBagConstraints.WEST, new Insets(2, 4, 4, 4)));

        this.addCustomComponent(0, chainGroupPanel);
    }

    private String getChainText() {
        return chainTextArea.getText();
    }

    private void setChainText(String text) {
        chainTextArea.setText(text);
    }

    private static boolean isChainConfigured(ScriptJobParameters parameters) {
        List<String> chain = parameters.getChain();
        return chain != null && !chain.isEmpty();
    }

    private File getDefaultDirectory() {
        return new File(System.getProperty("user.home"));
    }

    private ScriptAction getScriptAction() {
        return ScriptJob.createScriptAction(
                new ScriptJobParameters(this.getStringValue(SCRIPT_ACTION_PARAM)), null);
    }

    private boolean isRunAction() {
        return RunScriptAction.NAME.equalsIgnoreCase(this.getStringValue(SCRIPT_ACTION_PARAM));
    }

    private boolean isStandaloneType() {
        return ExtensionScript.TYPE_STANDALONE.equals(this.getStringValue(SCRIPT_TYPE_PARAM));
    }

    private boolean isUseChainMode() {
        return useChainCheckBox.isSelected();
    }

    private void onScriptActionChanged() {
        ScriptAction sa = getScriptAction();
        List<String> scriptTypes = sa.getSupportedScriptTypes();
        this.setComboFields(
                SCRIPT_TYPE_PARAM, scriptTypes, this.job.getData().getParameters().getType());

        List<String> disabledFields = sa.getDisabledFields();
        for (String fieldName : ALL_FIELDS) {
            Component field = this.getField(fieldName);
            if (field == null) {
                continue;
            }
            if (disabledFields.contains(fieldName)) {
                saveFieldValue(fieldName);
                if (field instanceof JTextComponent || field instanceof ZapTextArea) {
                    this.setFieldValue(fieldName, "");
                } else if (field instanceof JComboBox) {
                    ((JComboBox<?>) field).setSelectedIndex(0);
                }
                field.setEnabled(false);
            } else {
                field.setEnabled(true);
                restoreFieldValue(fieldName);
            }
        }

        onScriptTypeChanged();
    }

    private void onScriptTypeChanged() {
        String scriptType = this.getStringValue(SCRIPT_TYPE_PARAM);

        onScriptTypeTarget(scriptType);

        List<String> scripts = ScriptAction.getAvailableScriptNames(scriptType);
        // Always have a blank option at the start
        scripts.add(0, "");
        this.setComboFields(
                SCRIPT_NAME_PARAM, scripts, this.job.getData().getParameters().getName());

        updateChainFieldVisibility();
    }

    private void onUseChainChanged() {
        if (isUseChainMode()) {
            saveFieldValue(SCRIPT_NAME_PARAM);
            this.setFieldValue(SCRIPT_NAME_PARAM, "");
        } else {
            restoreFieldValue(SCRIPT_NAME_PARAM);
        }
        updateChainFieldVisibility();
    }

    private void onChainTextChanged() {
        if (!isRunAction() || !isStandaloneType()) {
            return;
        }
        if (StringUtils.isNotBlank(getChainText()) && !isUseChainMode()) {
            useChainCheckBox.setSelected(true);
            onUseChainChanged();
        }
    }

    private void updateChainFieldVisibility() {
        boolean chainUiEnabled = isRunAction() && isStandaloneType();
        if (chainGroupPanel != null) {
            chainGroupPanel.setVisible(chainUiEnabled);
        }
        if (useChainCheckBox != null) {
            useChainCheckBox.setEnabled(chainUiEnabled);
            if (!chainUiEnabled) {
                useChainCheckBox.setSelected(false);
            }
        }
        if (chainTextArea != null) {
            chainTextArea.setEnabled(chainUiEnabled);
        }
        if (fillChainButton != null) {
            fillChainButton.setEnabled(chainUiEnabled);
        }

        boolean useChain = chainUiEnabled && isUseChainMode();
        Component nameField = this.getField(SCRIPT_NAME_PARAM);
        if (nameField != null) {
            if (useChain) {
                nameField.setEnabled(false);
            } else {
                nameField.setEnabled(
                        !getScriptAction().getDisabledFields().contains(SCRIPT_NAME_PARAM));
            }
        }
    }

    private void fillChainFromPriorAddJobs() {
        List<String> priorNames = ScriptChainPlanSupport.priorStandaloneAddScriptNames(job);
        if (priorNames.isEmpty()) {
            View.getSingleton()
                    .showMessageDialog(
                            this,
                            Constant.messages.getString(
                                    "scripts.automation.dialog.chain.noPriorAdds"));
            return;
        }
        String existing = getChainText();
        String filled = ScriptChainPlanSupport.formatChainText(priorNames);
        if (StringUtils.isBlank(existing)) {
            setChainText(filled);
        } else {
            setChainText(existing.trim() + "\n" + filled);
        }
        if (!isUseChainMode()) {
            useChainCheckBox.setSelected(true);
            onUseChainChanged();
        }
    }

    private void onScriptNameChanged() {
        ScriptAction sa = getScriptAction();
        if (!sa.getDisabledFields().contains(SCRIPT_FILE_PARAM)
                && !this.getBoolValue(SCRIPT_IS_INLINE_PARAM)) {
            String scriptName = this.getStringValue(SCRIPT_NAME_PARAM);
            ScriptWrapper sw = ScriptAction.getExtScript().getScript(scriptName);
            if (sw != null && sw.getFile() != null) {
                this.setFieldValue(SCRIPT_FILE_PARAM, sw.getFile().getAbsolutePath());
            }
        }
    }

    private void saveFieldValue(String label) {
        Component c = this.getField(label);
        if (c instanceof JTextComponent || c instanceof ZapTextArea || c instanceof JComboBox) {
            String value = this.getStringValue(label);
            if (StringUtils.isNotBlank(value)) {
                this.lastValues.put(label, value);
            }
        }
    }

    private void restoreFieldValue(String label) {
        String value = this.lastValues.get(label);
        if (value != null) {
            this.setFieldValue(label, value);
        }
    }

    private void onIsInlineChanged() {
        if (this.getBoolValue(SCRIPT_IS_INLINE_PARAM)) {
            // Save in case this was a test/mistake
            saveFieldValue(SCRIPT_FILE_PARAM);
            this.setFieldValue(SCRIPT_FILE_PARAM, "");
            this.getField(SCRIPT_INLINE_PARAM).setEnabled(true);
            restoreFieldValue(SCRIPT_INLINE_PARAM);
        } else {
            // Save in case this was a test/mistake
            saveFieldValue(SCRIPT_INLINE_PARAM);
            this.setFieldValue(SCRIPT_INLINE_PARAM, "");
            this.getField(SCRIPT_INLINE_PARAM).setEnabled(false);
            restoreFieldValue(SCRIPT_FILE_PARAM);
        }
    }

    private ScriptJobParameters buildParametersFromFields() {
        List<String> chain = null;
        String scriptName = this.getStringValue(SCRIPT_NAME_PARAM);
        String chainText = getChainText();
        if (isRunAction()
                && isStandaloneType()
                && (isUseChainMode() || StringUtils.isNotBlank(chainText))) {
            chain = ScriptChainPlanSupport.parseChainText(chainText);
            scriptName = "";
        }
        return new ScriptJobParameters(
                this.getStringValue(SCRIPT_ACTION_PARAM),
                this.getStringValue(SCRIPT_TYPE_PARAM),
                this.getStringValue(SCRIPT_ENGINE_PARAM),
                scriptName,
                this.getStringValue(SCRIPT_FILE_PARAM),
                this.getStringValue(SCRIPT_TARGET_PARAM),
                this.getStringValue(SCRIPT_INLINE_PARAM),
                this.getStringValue(SCRIPT_CONTEXT_PARAM),
                this.getStringValue(SCRIPT_USER_PARAM),
                chain);
    }

    @Override
    public void save() {
        this.job.getData().setName(this.getStringValue(NAME_PARAM));
        this.job.getParameters().setContext(this.getStringValue(SCRIPT_CONTEXT_PARAM));
        this.job.getParameters().setUser(this.getStringValue(SCRIPT_USER_PARAM));
        this.job.getData().getParameters().setAction(this.getStringValue(SCRIPT_ACTION_PARAM));
        this.job.getData().getParameters().setType(this.getStringValue(SCRIPT_TYPE_PARAM));
        this.job.getData().getParameters().setEngine(this.getStringValue(SCRIPT_ENGINE_PARAM));
        this.job.getData().getParameters().setTarget(this.getStringValue(SCRIPT_TARGET_PARAM));
        this.job.getData().getParameters().setInline(this.getStringValue(SCRIPT_INLINE_PARAM));

        ScriptJobParameters params = buildParametersFromFields();
        this.job.getData().getParameters().setName(params.getName());
        this.job.getData().getParameters().setChain(params.getChain());

        ScriptAction sa = getScriptAction();
        if (sa.getDisabledFields().contains(SCRIPT_FILE_PARAM)) {
            this.job.getData().getParameters().setSource(null);
        } else {
            File f = new File(this.getStringValue(SCRIPT_FILE_PARAM));
            if (f.exists()) {
                this.job
                        .getData()
                        .getParameters()
                        .setSource(this.getStringValue(SCRIPT_FILE_PARAM));
            }
        }
        this.job.resetAndSetChanged();
    }

    @Override
    public String validateFields() {
        ScriptAction sa = getScriptAction();
        if (sa.getDisabledFields().contains(SCRIPT_FILE_PARAM)) {
            // Always unset this as the text field cannot be edited
            this.setFieldValue(SCRIPT_FILE_PARAM, null);
        }
        ScriptJobParameters params = buildParametersFromFields();
        sa = ScriptJob.createScriptAction(params, null);
        List<String> issues = sa.verifyParameters(this.getStringValue(NAME_PARAM), params, null);
        if (issues.isEmpty()) {
            // No problems
            return null;
        }
        return issues.stream().collect(Collectors.joining("\n"));
    }

    private void onScriptTypeTarget(String scriptType) {
        if (RunScriptAction.NAME.equals(getScriptAction().getName())) {
            if (ExtensionScript.TYPE_TARGETED.equals(scriptType)) {
                this.getField(SCRIPT_TARGET_PARAM).setEnabled(true);
                this.getField(SCRIPT_ENGINE_PARAM).setEnabled(true);
            } else {
                this.getField(SCRIPT_TARGET_PARAM).setEnabled(false);
                this.setFieldValue(SCRIPT_TARGET_PARAM, "");
                this.getField(SCRIPT_ENGINE_PARAM).setEnabled(false);
                this.setFieldValue(SCRIPT_ENGINE_PARAM, "");
            }
        }
    }
}
