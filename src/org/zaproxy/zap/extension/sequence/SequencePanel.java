/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP development team
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

package org.zaproxy.zap.extension.sequence;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.event.TableModelEvent;
import javax.swing.table.AbstractTableModel;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.AbstractParamContainerPanel;
import org.parosproxy.paros.view.AbstractParamPanel;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.utils.DisplayUtils;

public class SequencePanel extends AbstractParamPanel {

	private static final long serialVersionUID = 1L;

	private JTable tblSequence;
	private SequenceScriptsTableModel scriptsTableModel;

	private static final String PANEL_DESCRIPTION_LABEL = Constant.messages.getString("sequence.custom.tab.description");

	private static final String BTNINCLUDESELECT = Constant.messages.getString("sequence.custom.tab.selectall.label");
	private static final String BTNINCLUDEDESELECT = Constant.messages.getString("sequence.custom.tab.deselectall.label");
	
	private static final String TBLSEQHEADER0 = Constant.messages.getString("sequence.custom.tab.name.header");
	private static final String TBLSEQHEADER1 = Constant.messages.getString("sequence.custom.tab.inc.header");
	
	private static final String HELPSTRING = "ui.dialogs.sequence";

	private JButton btnInclude = null; 
	private JButton btnHelp = null;
	
	/**
	 * Creates a new instance of the Sequence Panel.
	 * 
	 * @param extensionScript the extension used to obtain the Sequence scripts.
	 */
	public SequencePanel(ExtensionScript extensionScript) {
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{0, 0};
		gridBagLayout.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);

		JLabel labelTop = new JLabel(PANEL_DESCRIPTION_LABEL);
		GridBagConstraints gbc_labelTop = new GridBagConstraints();
		gbc_labelTop.anchor = GridBagConstraints.NORTHWEST;
		gbc_labelTop.insets = new Insets(15, 15, 5, 0);
		gbc_labelTop.gridx = 0;
		gbc_labelTop.gridy = 0;
		add(labelTop, gbc_labelTop);

		btnInclude = new JButton(BTNINCLUDESELECT);
		btnInclude.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				boolean selectScripts;
				if(btnInclude.getText().equals(BTNINCLUDESELECT)) {
					selectScripts = true;
					btnInclude.setText(BTNINCLUDEDESELECT);
				}
				else {
					selectScripts = false;
					btnInclude.setText(BTNINCLUDESELECT);
				}
				scriptsTableModel.setAllSelected(selectScripts);
			}
		});
		GridBagConstraints gbc_btnInclude = new GridBagConstraints();
		gbc_btnInclude.anchor = GridBagConstraints.NORTHWEST;
		gbc_btnInclude.insets = new Insets(0, 15, 5, 0);
		gbc_btnInclude.gridx = 0;
		gbc_btnInclude.gridy = 1;
		add(btnInclude, gbc_btnInclude);

		JScrollPane scrollPane = new JScrollPane();
		GridBagConstraints gbc_scrollPane = new GridBagConstraints();
		gbc_scrollPane.anchor = GridBagConstraints.NORTHWEST;
		gbc_scrollPane.gridheight = 3;
		gbc_scrollPane.insets = new Insets(15, 15, 15, 15);
		gbc_scrollPane.fill = GridBagConstraints.BOTH;
		gbc_scrollPane.gridx = 0;
		gbc_scrollPane.gridy = 3;
		add(scrollPane, gbc_scrollPane);

		tblSequence = new JTable();
		
		scriptsTableModel = new SequenceScriptsTableModel(extensionScript.getScripts(ExtensionSequence.TYPE_SEQUENCE));
		tblSequence.setModel(scriptsTableModel);

		tblSequence.getColumnModel().getColumn(0).setPreferredWidth(525);
		tblSequence.getColumnModel().getColumn(0).setMinWidth(25);
		tblSequence.getColumnModel().getColumn(1).setPreferredWidth(100);
		tblSequence.getColumnModel().getColumn(1).setMinWidth(100);
		scrollPane.setViewportView(tblSequence);


		// TODO no help available yet
		//add(getHelpButton());
	}

	private JButton getHelpButton() {
		if (btnHelp == null) {
			btnHelp = new JButton();
			btnHelp.setBorder(null);
			btnHelp.setIcon(DisplayUtils.getScaledIcon(
					new ImageIcon(AbstractParamContainerPanel.class.getResource("/resource/icon/16/201.png")))); // help icon
			btnHelp.addActionListener(
					new ActionListener() {

						@Override
						public void actionPerformed(ActionEvent arg0) {
							ExtensionHelp.showHelp(HELPSTRING);

						}
					});
			btnHelp.setToolTipText(Constant.messages.getString("menu.help"));
		}
		return btnHelp;
	}

	/**
	 * Gets a list of Sequence Scripts, that were selected in the "Include" column.
	 * @return A list of the selected Sequence scripts in the "Include" column.
	 */
	public List<ScriptWrapper> getSelectedIncludeScripts() {
		return scriptsTableModel.getSelectedScripts();
	}

	
	@Override
	public void initParam(Object obj) {
	}

	@Override
	public void validateParam(Object obj) throws Exception {
	}

	@Override
	public void saveParam(Object obj) throws Exception {
	}

	@Override
	public String getHelpIndex() {
		// TODO no help available yet
		//return HELPSTRING;
		return null;
	}
	
	private static class SequenceScriptsTableModel extends AbstractTableModel {

		private static final long serialVersionUID = 1L;

		private static final String[] COLUMN_NAMES = { TBLSEQHEADER0, TBLSEQHEADER1 };

		private static final int COLUMN_COUNT = COLUMN_NAMES.length;

		private final List<ScriptWrapperUI> scriptsUI;

		public SequenceScriptsTableModel(List<ScriptWrapper> scripts) {
			scriptsUI = new ArrayList<>(scripts.size());
			for (ScriptWrapper sw : scripts) {
				scriptsUI.add(new ScriptWrapperUI(sw));
			}
		}

		@Override
		public String getColumnName(int col) {
			return COLUMN_NAMES[col];
		}

		@Override
		public int getColumnCount() {
			return COLUMN_COUNT;
		}

		@Override
		public int getRowCount() {
			return scriptsUI.size();
		}

		@Override
		public Object getValueAt(int rowIndex, int columnIndex) {
			if (columnIndex == 1) {
				return Boolean.valueOf(scriptsUI.get(rowIndex).isSelected());
			}
			return scriptsUI.get(rowIndex).getName();
		}

		@Override
		public boolean isCellEditable(int row, int column) {
			if (column == 1) {
				return true;
			}
			return false;
		}

		@Override
		public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
			if (columnIndex == 1) {
				scriptsUI.get(rowIndex).setSelected(((Boolean) aValue).booleanValue());
				fireTableCellUpdated(rowIndex, columnIndex);
			}
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			if (columnIndex == 1) {
				return Boolean.class;
			}
			return String.class;
		}

		public List<ScriptWrapper> getSelectedScripts() {
			ArrayList<ScriptWrapper> sws = new ArrayList<>(scriptsUI.size());
			for (ScriptWrapperUI swUI : scriptsUI) {
				if (swUI.isSelected()) {
					sws.add(swUI.getScriptWrapper());
				}
			}
			sws.trimToSize();
			return sws;
		}

		public void setAllSelected(boolean selected) {
			final int size = scriptsUI.size();
			if (size > 0) {
				for (ScriptWrapperUI swUI : scriptsUI) {
					swUI.setSelected(selected);
				}

				fireTableChanged(new TableModelEvent(this, 0, size - 1, 1, TableModelEvent.UPDATE));
			}
		}

		private static class ScriptWrapperUI {

			private final ScriptWrapper script;
			private boolean selected;

			public ScriptWrapperUI(ScriptWrapper script) {
				this.script = script;
			}

			public boolean isSelected() {
				return selected;
			}

			public void setSelected(boolean selected) {
				this.selected = selected;
			}

			public String getName() {
				return script.getName();
			}

			public ScriptWrapper getScriptWrapper() {
				return script;
			}
		}
	}
}
