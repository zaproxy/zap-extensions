/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.alertFilters;

import java.awt.Component;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.AbstractFormDialog;
import org.zaproxy.zap.view.LayoutHelper;

/** The Dialog for adding and configuring a new {@link AlertFilter}. */
@SuppressWarnings("serial")
public class DialogAddAlertFilter extends AbstractFormDialog {

    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = -7210879426146833234L;

    /** The Constant logger. */
    protected static final Logger log = LogManager.getLogger(DialogAddAlertFilter.class);

    private static final String DIALOG_TITLE =
            Constant.messages.getString("alertFilters.dialog.add.title");
    private static final String CONFIRM_BUTTON_LABEL =
            Constant.messages.getString("alertFilters.dialog.add.button.confirm");

    private static final String SCOPE_GLOBAL =
            Constant.messages.getString("alertFilters.dialog.add.label.scope.global");

    private ExtensionAlertFilters extension;
    private JPanel fieldsPanel;
    private Insets insets = new Insets(4, 8, 2, 4);
    private JCheckBox enabledCheckBox;
    private JComboBox<String> alertCombo;
    private JComboBox<String> newLevelCombo;
    private ZapTextField urlTextField;
    private JCheckBox urlRegexCheckBox;
    private ZapTextField paramTextField;
    private JCheckBox paramRegexCheckBox;
    private ZapTextField attackTextField;
    private JCheckBox attackRegexCheckBox;
    private ZapTextField evidenceTextField;
    private JCheckBox evidenceRegexCheckBox;
    private JLabel scopeLabel;
    private JLabel scopeFixed;
    private JComboBox<String> scopeCombo;
    private Component scopeComponent;
    private boolean canChangeContext;
    private int scopeYOffset;
    private Context workingContext;
    private AlertFilter oldAlertFilter;
    private AlertFilter alertFilter;
    private JButton testButton;
    private JButton applyButton;
    private JLabel testResultsLabel;
    private JLabel applyResultsLabel;

    /**
     * Instantiates a new dialog add alertFilter.
     *
     * @param owner the owner
     */
    public DialogAddAlertFilter(ExtensionAlertFilters extension, Window owner) {
        this(extension, owner, DIALOG_TITLE);
    }

    /**
     * Instantiates a new dialog add alertFilter.
     *
     * @param owner the owner
     * @param title the title
     */
    public DialogAddAlertFilter(ExtensionAlertFilters extension, Window owner, String title) {
        super(owner, title);
        this.extension = extension;
    }

    /**
     * Sets the context on which the Dialog is working.
     *
     * @param context the new working context
     */
    public void setWorkingContext(Context context) {
        this.workingContext = context;
    }

    public void setCanChangeContext(boolean canChangeContext) {
        this.canChangeContext = canChangeContext;
        if (scopeComponent != null) {
            fieldsPanel.remove(scopeComponent);
        }
        if (canChangeContext) {
            scopeComponent = getScopeCombo();
            resetScopeCombo();
        } else {
            scopeComponent = getScopeFixed();
        }
        scopeLabel.setLabelFor(scopeComponent);
        fieldsPanel.add(scopeComponent, LayoutHelper.getGBC(1, scopeYOffset, 3, 0.5D, insets));
        this.pack();
    }

    @Override
    protected void init() {
        if (this.oldAlertFilter != null) {
            log.debug("Initializing add alertFilter dialog for: {}", oldAlertFilter);
            getAlertCombo()
                    .setSelectedItem(
                            ExtensionAlertFilters.getRuleNameForId(oldAlertFilter.getRuleId()));
            getNewLevelCombo()
                    .setSelectedItem(AlertFilter.getNameForRisk(oldAlertFilter.getNewRisk()));
            getUrlTextField().setText(oldAlertFilter.getUrl());
            getUrlRegexCheckBox().setSelected(oldAlertFilter.isUrlRegex());
            getParamTextField().setText(oldAlertFilter.getParameter());
            getParamRegexCheckBox().setSelected(oldAlertFilter.isParameterRegex());
            getAttackTextField().setText(oldAlertFilter.getAttack());
            getAttackRegexCheckBox().setSelected(oldAlertFilter.isAttackRegex());
            getEvidenceTextField().setText(oldAlertFilter.getEvidence());
            getEvidenceRegexCheckBox().setSelected(oldAlertFilter.isEvidenceRegex());

            getEnabledCheckBox().setSelected(oldAlertFilter.isEnabled());
            setButtonStates();
        }
        this.setConfirmButtonEnabled(true);
    }

    private boolean regexFieldValid(ZapTextField field, String error) {
        try {
            Pattern.compile(field.getText());
        } catch (PatternSyntaxException e) {
            JOptionPane.showMessageDialog(
                    this,
                    error,
                    Constant.messages.getString("alertFilters.dialog.error.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            field.requestFocusInWindow();
            return false;
        }
        return true;
    }

    @Override
    protected boolean validateFields() {
        if (getAlertCombo().getSelectedItem() == null) {
            // Will happen with custom alerts
            JOptionPane.showMessageDialog(
                    this,
                    Constant.messages.getString("alertFilters.dialog.error.missing.rule"),
                    Constant.messages.getString("alertFilters.dialog.error.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            return false;
        }

        if (this.getUrlRegexCheckBox().isSelected()) {
            if (!regexFieldValid(
                    this.getUrlTextField(),
                    Constant.messages.getString("alertFilters.dialog.error.badregex.url"))) {
                return false;
            }
        }
        if (this.getParamRegexCheckBox().isSelected()) {
            if (!regexFieldValid(
                    this.getParamTextField(),
                    Constant.messages.getString("alertFilters.dialog.error.badregex.param"))) {
                return false;
            }
        }
        if (this.getAttackRegexCheckBox().isSelected()) {
            if (!regexFieldValid(
                    this.getAttackTextField(),
                    Constant.messages.getString("alertFilters.dialog.error.badregex.attack"))) {
                return false;
            }
        }
        if (this.getEvidenceRegexCheckBox().isSelected()) {
            if (!regexFieldValid(
                    this.getEvidenceTextField(),
                    Constant.messages.getString("alertFilters.dialog.error.badregex.evidence"))) {
                return false;
            }
        }
        return true;
    }

    @Override
    protected void performAction() {
        this.alertFilter = fieldsToFilter();
    }

    private AlertFilter fieldsToFilter() {
        String alertName = (String) getAlertCombo().getSelectedItem();
        if (canChangeContext) {
            workingContext = this.getChosenContext();
        }

        return new AlertFilter(
                workingContext != null ? workingContext.getId() : -1,
                ExtensionAlertFilters.getIdForRuleName(alertName),
                getNewLevel(),
                getUrlTextField().getText(),
                getUrlRegexCheckBox().isSelected(),
                getParamTextField().getText(),
                getParamRegexCheckBox().isSelected(),
                getAttackTextField().getText(),
                getAttackRegexCheckBox().isSelected(),
                getEvidenceTextField().getText(),
                getEvidenceRegexCheckBox().isSelected(),
                this.getEnabledCheckBox().isSelected());
    }

    @Override
    protected void clearFields() {
        this.oldAlertFilter = null;
        this.enabledCheckBox.setSelected(true);
        this.alertCombo.setSelectedIndex(0);
        this.newLevelCombo.setSelectedIndex(0);
        this.urlTextField.setText("");
        this.urlTextField.discardAllEdits();
        this.urlRegexCheckBox.setSelected(false);
        this.paramTextField.setText("");
        this.paramTextField.discardAllEdits();
        this.paramRegexCheckBox.setSelected(false);
        this.attackTextField.setText("");
        this.attackTextField.discardAllEdits();
        this.attackRegexCheckBox.setSelected(false);
        this.evidenceTextField.setText("");
        this.evidenceTextField.discardAllEdits();
        this.evidenceRegexCheckBox.setSelected(false);
        this.setConfirmButtonEnabled(true);
        this.testResultsLabel.setText(
                Constant.messages.getString("alertFilters.dialog.filter.state.nottested"));
        this.applyResultsLabel.setText(
                Constant.messages.getString("alertFilters.dialog.filter.state.notapplied"));
    }

    public void setAlertFilter(AlertFilter alertFilter) {
        this.oldAlertFilter = alertFilter;
        this.alertFilter = null;
        setButtonStates();
    }

    /**
     * Gets the {@code AlertFilter} defined in the dialog, will be null if the dialog is cancelled.
     *
     * @return the {@code AlertFilter}, if correctly built or null otherwise
     */
    public AlertFilter getAlertFilter() {
        return alertFilter;
    }

    @Override
    protected JPanel getFieldsPanel() {
        if (fieldsPanel == null) {
            fieldsPanel = new JPanel();

            fieldsPanel.setLayout(new GridBagLayout());
            fieldsPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
            fieldsPanel.setName("DialogAddAlertFilter");
            int y = 0;

            scopeLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "alertFilters.dialog.add.field.label.scope"));
            scopeComponent = getScopeFixed();
            scopeLabel.setLabelFor(scopeComponent);
            scopeYOffset = y;
            fieldsPanel.add(scopeLabel, LayoutHelper.getGBC(0, y, 1, 0.5D, insets));
            fieldsPanel.add(scopeComponent, LayoutHelper.getGBC(1, y, 2, 0.5D, insets));

            JLabel alertLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "alertFilters.dialog.add.field.label.alert"));
            alertLabel.setLabelFor(getAlertCombo());
            fieldsPanel.add(alertLabel, LayoutHelper.getGBC(0, ++y, 1, 0.5D, insets));
            fieldsPanel.add(getAlertCombo(), LayoutHelper.getGBC(1, y, 2, 0.5D, insets));

            JLabel newLevelLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "alertFilters.dialog.add.field.label.newlevel"));
            newLevelLabel.setLabelFor(getNewLevelCombo());
            fieldsPanel.add(newLevelLabel, LayoutHelper.getGBC(0, ++y, 1, 0.5D, insets));
            fieldsPanel.add(getNewLevelCombo(), LayoutHelper.getGBC(1, y, 2, 0.5D, insets));

            JLabel urlLabel =
                    new JLabel(
                            Constant.messages.getString("alertFilters.dialog.add.field.label.url"));
            urlLabel.setLabelFor(getUrlTextField());
            fieldsPanel.add(urlLabel, LayoutHelper.getGBC(0, ++y, 1, 0.5D, insets));
            fieldsPanel.add(getUrlTextField(), LayoutHelper.getGBC(1, y, 2, 0.5D, insets));

            JLabel urlRegexLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "alertFilters.dialog.add.field.label.urlregex"));
            urlRegexLabel.setLabelFor(getUrlRegexCheckBox());
            fieldsPanel.add(urlRegexLabel, LayoutHelper.getGBC(0, ++y, 1, 0.5D, insets));
            fieldsPanel.add(getUrlRegexCheckBox(), LayoutHelper.getGBC(1, y, 2, 0.5D, insets));

            JLabel paramLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "alertFilters.dialog.add.field.label.param"));
            paramLabel.setLabelFor(getParamTextField());
            fieldsPanel.add(paramLabel, LayoutHelper.getGBC(0, ++y, 1, 0.5D, insets));
            fieldsPanel.add(getParamTextField(), LayoutHelper.getGBC(1, y, 2, 0.5D, insets));

            JLabel paramRegexLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "alertFilters.dialog.add.field.label.paramregex"));
            paramRegexLabel.setLabelFor(getParamRegexCheckBox());
            fieldsPanel.add(paramRegexLabel, LayoutHelper.getGBC(0, ++y, 1, 0.5D, insets));
            fieldsPanel.add(getParamRegexCheckBox(), LayoutHelper.getGBC(1, y, 2, 0.5D, insets));

            JLabel attackLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "alertFilters.dialog.add.field.label.attack"));
            attackLabel.setLabelFor(getAttackTextField());
            fieldsPanel.add(attackLabel, LayoutHelper.getGBC(0, ++y, 1, 0.5D, insets));
            fieldsPanel.add(getAttackTextField(), LayoutHelper.getGBC(1, y, 2, 0.5D, insets));

            JLabel attackRegexLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "alertFilters.dialog.add.field.label.attackregex"));
            attackRegexLabel.setLabelFor(getUrlRegexCheckBox());
            fieldsPanel.add(attackRegexLabel, LayoutHelper.getGBC(0, ++y, 1, 0.5D, insets));
            fieldsPanel.add(getAttackRegexCheckBox(), LayoutHelper.getGBC(1, y, 2, 0.5D, insets));

            JLabel evidenceLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "alertFilters.dialog.add.field.label.evidence"));
            evidenceLabel.setLabelFor(getEvidenceTextField());
            fieldsPanel.add(evidenceLabel, LayoutHelper.getGBC(0, ++y, 1, 0.5D, insets));
            fieldsPanel.add(getEvidenceTextField(), LayoutHelper.getGBC(1, y, 2, 0.5D, insets));

            JLabel evidenceRegexLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "alertFilters.dialog.add.field.label.evidenceregex"));
            evidenceRegexLabel.setLabelFor(getUrlRegexCheckBox());
            fieldsPanel.add(evidenceRegexLabel, LayoutHelper.getGBC(0, ++y, 1, 0.5D, insets));
            fieldsPanel.add(getEvidenceRegexCheckBox(), LayoutHelper.getGBC(1, y, 2, 0.5D, insets));

            JLabel enabledLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "alertFilters.dialog.add.field.label.enabled"));
            enabledLabel.setLabelFor(getEnabledCheckBox());
            fieldsPanel.add(enabledLabel, LayoutHelper.getGBC(0, ++y, 1, 0.5D, insets));
            fieldsPanel.add(getEnabledCheckBox(), LayoutHelper.getGBC(1, y, 2, 0.5D, insets));

            testResultsLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "alertFilters.dialog.filter.state.nottested"));
            testButton =
                    new JButton(Constant.messages.getString("alertFilters.dialog.button.test"));
            testButton.addActionListener(
                    e -> {
                        oldAlertFilter = fieldsToFilter();
                        if (validateFields()) {
                            int count = extension.applyAlertFilter(oldAlertFilter, true);
                            testResultsLabel.setText(
                                    Constant.messages.getString(
                                            "alertFilters.dialog.filter.state.appliesto", count));
                        }
                    });
            JLabel testFilterLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "alertFilters.dialog.add.field.label.test"));
            testFilterLabel.setLabelFor(testButton);
            fieldsPanel.add(testFilterLabel, LayoutHelper.getGBC(0, ++y, 1, 0.5D, insets));
            fieldsPanel.add(testButton, LayoutHelper.getGBC(1, y, 1, 0D, insets));
            fieldsPanel.add(testResultsLabel, LayoutHelper.getGBC(2, y, 1, 1.0D, insets));

            applyResultsLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "alertFilters.dialog.filter.state.notapplied"));
            applyButton =
                    new JButton(Constant.messages.getString("alertFilters.dialog.button.apply"));
            applyButton.addActionListener(
                    e -> {
                        oldAlertFilter = fieldsToFilter();
                        if (validateFields()) {
                            int count = extension.applyAlertFilter(oldAlertFilter, false);
                            applyResultsLabel.setText(
                                    Constant.messages.getString(
                                            "alertFilters.dialog.filter.state.appliedto", count));
                        }
                    });
            JLabel applyFilterLabel =
                    new JLabel(
                            Constant.messages.getString(
                                    "alertFilters.dialog.add.field.label.apply"));
            applyFilterLabel.setLabelFor(testButton);
            fieldsPanel.add(applyFilterLabel, LayoutHelper.getGBC(0, ++y, 1, 0.5D, insets));
            fieldsPanel.add(applyButton, LayoutHelper.getGBC(1, y, 1, 0D, insets));
            fieldsPanel.add(applyResultsLabel, LayoutHelper.getGBC(2, y, 1, 1.0D, insets));

            fieldsPanel.add(new JLabel(), LayoutHelper.getGBC(0, ++y, 2, 1.0D)); // Spacer
        }
        return fieldsPanel;
    }

    protected JCheckBox getEnabledCheckBox() {
        if (enabledCheckBox == null) {
            enabledCheckBox = new JCheckBox();
            enabledCheckBox.setSelected(true);
            enabledCheckBox.addActionListener(e -> setButtonStates());
        }

        return enabledCheckBox;
    }

    protected void setButtonStates() {
        if (testButton != null) {
            testButton.setEnabled(enabledCheckBox.isSelected());
        }
        if (applyButton != null) {
            applyButton.setEnabled(enabledCheckBox.isSelected());
        }
    }

    protected ZapTextField getUrlTextField() {
        if (urlTextField == null) {
            urlTextField = new ZapTextField();
        }
        return urlTextField;
    }

    protected JCheckBox getUrlRegexCheckBox() {
        if (urlRegexCheckBox == null) {
            urlRegexCheckBox = new JCheckBox();
        }
        return urlRegexCheckBox;
    }

    protected ZapTextField getParamTextField() {
        if (paramTextField == null) {
            paramTextField = new ZapTextField();
        }
        return paramTextField;
    }

    protected JCheckBox getParamRegexCheckBox() {
        if (paramRegexCheckBox == null) {
            paramRegexCheckBox = new JCheckBox();
        }
        return paramRegexCheckBox;
    }

    protected ZapTextField getAttackTextField() {
        if (attackTextField == null) {
            attackTextField = new ZapTextField();
        }
        return attackTextField;
    }

    protected JCheckBox getAttackRegexCheckBox() {
        if (attackRegexCheckBox == null) {
            attackRegexCheckBox = new JCheckBox();
        }
        return attackRegexCheckBox;
    }

    protected ZapTextField getEvidenceTextField() {
        if (evidenceTextField == null) {
            evidenceTextField = new ZapTextField();
        }
        return evidenceTextField;
    }

    protected JCheckBox getEvidenceRegexCheckBox() {
        if (evidenceRegexCheckBox == null) {
            evidenceRegexCheckBox = new JCheckBox();
        }
        return evidenceRegexCheckBox;
    }

    protected JComboBox<String> getAlertCombo() {
        if (alertCombo == null) {
            alertCombo = new JComboBox<>();
            for (String name : ExtensionAlertFilters.getAllRuleNames()) {
                alertCombo.addItem(name);
            }
        }
        return alertCombo;
    }

    protected JComboBox<String> getNewLevelCombo() {
        if (newLevelCombo == null) {
            newLevelCombo = new JComboBox<>();
            newLevelCombo.addItem(AlertFilter.getNameForRisk(-1));
            newLevelCombo.addItem(AlertFilter.getNameForRisk(0));
            newLevelCombo.addItem(AlertFilter.getNameForRisk(1));
            newLevelCombo.addItem(AlertFilter.getNameForRisk(2));
            newLevelCombo.addItem(AlertFilter.getNameForRisk(3));
        }
        return newLevelCombo;
    }

    private int getNewLevel() {
        String level = (String) getNewLevelCombo().getSelectedItem();

        for (int i = -1; i < 4; i++) {
            if (AlertFilter.getNameForRisk(i).equals(level)) {
                return i;
            }
        }
        return -1;
    }

    @Override
    protected String getConfirmButtonLabel() {
        return CONFIRM_BUTTON_LABEL;
    }

    private JLabel getScopeFixed() {
        if (scopeFixed == null) {
            this.scopeFixed = new JLabel();
        }
        if (this.workingContext == null) {
            this.scopeFixed.setText(SCOPE_GLOBAL);
        } else {
            this.scopeFixed.setText(this.workingContext.getName());
        }
        return scopeFixed;
    }

    private void resetScopeCombo() {
        JComboBox<String> scopeCombo = getScopeCombo();
        scopeCombo.removeAllItems();
        scopeCombo.addItem(SCOPE_GLOBAL);
        for (Context context : Model.getSingleton().getSession().getContexts()) {
            scopeCombo.addItem(context.getName());
        }
    }

    private JComboBox<String> getScopeCombo() {
        if (scopeCombo == null) {
            scopeCombo = new JComboBox<>();
        }
        return scopeCombo;
    }

    private Context getChosenContext() {
        String name = (String) this.getScopeCombo().getSelectedItem();

        if (name.equals(SCOPE_GLOBAL)) {
            return null;
        }
        for (Context context : Model.getSingleton().getSession().getContexts()) {
            if (name.equals(context.getName())) {
                return context;
            }
        }
        return null;
    }
}
