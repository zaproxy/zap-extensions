/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright The ZAP Development Team
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.alertFilters;

import java.awt.Dialog;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.AbstractFormDialog;
import org.zaproxy.zap.view.LayoutHelper;

/**
 * The Dialog for adding and configuring a new {@link AlertFilter}.
 */
public class DialogAddAlertFilter extends AbstractFormDialog {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = -7210879426146833234L;

	/** The Constant logger. */
	protected static final Logger log = Logger.getLogger(DialogAddAlertFilter.class);

	private static final String DIALOG_TITLE = Constant.messages.getString("alertFilters.dialog.add.title");
	private static final String CONFIRM_BUTTON_LABEL = 
			Constant.messages.getString("alertFilters.dialog.add.button.confirm");

	//private ExtensionAlertFilters extension = null;
	private JPanel fieldsPanel;
	private JCheckBox enabledCheckBox;
	private JComboBox<String> alertCombo;
	private JComboBox<String> newLevelCombo;
	private ZapTextField urlTextField;
	private JCheckBox regexCheckBox;
	private ZapTextField paramTextField;
	protected Context workingContext;
	protected AlertFilter alertFilter;

	/**
	 * Instantiates a new dialog add alertFilter.
	 * 
	 * @param owner the owner
	 * @param extension the extension
	 * @param context the context
	 */
	public DialogAddAlertFilter(Dialog owner, ExtensionAlertFilters extension) {
		super(owner, DIALOG_TITLE);
		//this.extension = extension;
	}

	/**
	 * Instantiates a new dialog add alertFilter.
	 * 
	 * @param owner the owner
	 * @param extension the extension
	 * @param title the title
	 * @param context the context
	 */
	public DialogAddAlertFilter(Dialog owner, ExtensionAlertFilters extension, String title) {
		super(owner, title);
		//this.extension = extension;
	}

	/**
	 * Sets the context on which the Dialog is working.
	 * 
	 * @param context the new working context
	 */
	public void setWorkingContext(Context context) {
		this.workingContext = context;
	}

	@Override
	protected void init() {
		if (this.workingContext == null)
			throw new IllegalStateException(
					"A working Context should be set before setting the 'Add Dialog' visible.");

		this.setConfirmButtonEnabled(true);
	}

	public void clear() {
		this.alertFilter = null;
		this.workingContext = null;
	}

	@Override
	protected boolean validateFields() {
		// TODO check url / regex
		return true;
	}

	@Override
	protected void performAction() {
		String alertName = (String)getAlertCombo().getSelectedItem();
		this.alertFilter = new AlertFilter(
				workingContext.getIndex(), 
				ExtensionAlertFilters.getIdForRuleName(alertName),
				getNewLevel(),
				getUrlTextField().getText(),
				getRegexCheckBox().isSelected(),
				getParamTextField().getText(),
				this.getEnabledCheckBox().isSelected());
	}

	@Override
	protected void clearFields() {
		this.enabledCheckBox.setSelected(true);
		this.setConfirmButtonEnabled(true);
	}

	/**
	 * Gets the alertFilter defined in the dialog, if any.
	 * 
	 * @return the alertFilter, if correctly built or null, otherwise
	 */
	public AlertFilter getAlertFilter() {
		return alertFilter;
	}

	@Override
	protected JPanel getFieldsPanel() {
		if (fieldsPanel == null) {
			fieldsPanel = new JPanel();

			fieldsPanel.setLayout(new GridBagLayout());
			fieldsPanel.setName("DialogAddAlertFilter");
			Insets insets = new Insets(4, 8, 2, 4);

			JLabel alertLabel = new JLabel(
					Constant.messages.getString("alertFilters.dialog.add.field.label.alert"));
			alertLabel.setLabelFor(getAlertCombo());
			fieldsPanel.add(alertLabel, LayoutHelper.getGBC(0, 0, 1, 0.5D, insets));
			fieldsPanel.add(getAlertCombo(), LayoutHelper.getGBC(1, 0, 1, 0.5D, insets));
			
			JLabel newLevelLabel = new JLabel(
					Constant.messages.getString("alertFilters.dialog.add.field.label.newlevel"));
			newLevelLabel.setLabelFor(getNewLevelCombo());
			fieldsPanel.add(newLevelLabel, LayoutHelper.getGBC(0, 1, 1, 0.5D, insets));
			fieldsPanel.add(getNewLevelCombo(), LayoutHelper.getGBC(1, 1, 1, 0.5D, insets));
			
			JLabel urlLabel = new JLabel(
					Constant.messages.getString("alertFilters.dialog.add.field.label.url"));
			urlLabel.setLabelFor(getUrlTextField());
			fieldsPanel.add(urlLabel, LayoutHelper.getGBC(0, 2, 1, 0.5D, insets));
			fieldsPanel.add(getUrlTextField(), LayoutHelper.getGBC(1, 2, 1, 0.5D, insets));
			
			JLabel regexLabel = new JLabel(
					Constant.messages.getString("alertFilters.dialog.add.field.label.regex"));
			regexLabel.setLabelFor(getRegexCheckBox());
			fieldsPanel.add(regexLabel, LayoutHelper.getGBC(0, 3, 1, 0.5D, insets));
			fieldsPanel.add(getRegexCheckBox(), LayoutHelper.getGBC(1, 3, 1, 0.5D, insets));

			JLabel paramLabel = new JLabel(
					Constant.messages.getString("alertFilters.dialog.add.field.label.param"));
			paramLabel.setLabelFor(getParamTextField());
			fieldsPanel.add(paramLabel, LayoutHelper.getGBC(0, 4, 1, 0.5D, insets));
			fieldsPanel.add(getParamTextField(), LayoutHelper.getGBC(1, 4, 1, 0.5D, insets));
			
			JLabel enabledLabel = new JLabel(
					Constant.messages.getString("alertFilters.dialog.add.field.label.enabled"));
			enabledLabel.setLabelFor(getEnabledCheckBox());
			fieldsPanel.add(enabledLabel, LayoutHelper.getGBC(0, 5, 1, 0.5D, insets));
			fieldsPanel.add(getEnabledCheckBox(), LayoutHelper.getGBC(1, 5, 1, 0.5D, insets));

			fieldsPanel.add(new JLabel(), LayoutHelper.getGBC(0, 10, 2, 1.0D));	// Spacer

		}
		return fieldsPanel;
	}

	protected JCheckBox getEnabledCheckBox() {
		if (enabledCheckBox == null) {
			enabledCheckBox = new JCheckBox();
			enabledCheckBox.setSelected(true);
		}

		return enabledCheckBox;
	}

	protected ZapTextField getUrlTextField() {
		if (urlTextField == null) {
			urlTextField = new ZapTextField();
		}
		return urlTextField;
	}
	
	protected JCheckBox getRegexCheckBox() {
		if (regexCheckBox == null) {
			regexCheckBox = new JCheckBox();
		}
		return regexCheckBox;
	}
	
	protected ZapTextField getParamTextField() {
		if (paramTextField == null) {
			paramTextField = new ZapTextField();
		}
		return paramTextField;
	}

	protected JComboBox<String> getAlertCombo() {
		if (alertCombo == null) {
			alertCombo = new JComboBox<String>();
			for (String name : ExtensionAlertFilters.getAllRuleNames()) {
				alertCombo.addItem(name);
			}
		}
		return alertCombo;
	}
	
	protected JComboBox<String> getNewLevelCombo() {
		if (newLevelCombo == null) {
			newLevelCombo = new JComboBox<String>();
			newLevelCombo.addItem(AlertFilter.getNameForRisk(-1));
			newLevelCombo.addItem(AlertFilter.getNameForRisk(0));
			newLevelCombo.addItem(AlertFilter.getNameForRisk(1));
			newLevelCombo.addItem(AlertFilter.getNameForRisk(2));
			newLevelCombo.addItem(AlertFilter.getNameForRisk(3));
		}
		return newLevelCombo;
	}
	
	private int getNewLevel() {
		String level = (String)getNewLevelCombo().getSelectedItem();
		
		for (int i=-1; i < 4; i++) {
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

}
