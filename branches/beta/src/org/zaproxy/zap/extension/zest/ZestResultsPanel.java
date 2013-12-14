/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest;

import java.awt.CardLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.util.List;

import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.view.HistoryReferenceTable;
import org.zaproxy.zap.view.HistoryReferenceTableModel.COLUMN;
import org.zaproxy.zap.view.LayoutHelper;

public class ZestResultsPanel extends AbstractPanel {

	private static final long serialVersionUID = 1L;

	public static final String TABLE_NAME = "ZestResultsTable";
	
	private static COLUMN[] COLS = 
		{COLUMN.HREF_ID, COLUMN.METHOD, COLUMN.URL, COLUMN.CODE, COLUMN.REASON, COLUMN.RTT, COLUMN.SIZE, COLUMN.CUSTOM_1, COLUMN.CUSTOM_2};
	private static int[] SIZES = {20, 20, 400, 20, 80, 20, 40, 20, 400};
	
	@SuppressWarnings("unused")
	private ExtensionZest extension = null;

	private javax.swing.JPanel zestPanel = null;
	private JScrollPane jScrollPane = null;
	private HistoryReferenceTable resultsTable = null;
	private ZestResultsTableModel model = null;

	public ZestResultsPanel(ExtensionZest extension) {
		super();
		this.extension = extension;
		initialize();
	}
	
	private void initialize() {
        this.setLayout(new CardLayout());
        this.setName(Constant.messages.getString("zest.results.panel.title"));
		this.setIcon(ExtensionZest.ZEST_ICON);

        this.add(getZestPanel(), getZestPanel().getName());
			
	}

	private javax.swing.JPanel getZestPanel() {
		if (zestPanel == null) {

			zestPanel = new javax.swing.JPanel();
			zestPanel.setLayout(new java.awt.GridBagLayout());
			zestPanel.setName("ZestResultsPanel");
			zestPanel.add(getJScrollPane(), 
					LayoutHelper.getGBC(0, 1, 1, 1.0, 1.0, GridBagConstraints.BOTH, new Insets(2,2,2,2)));

		}
		return zestPanel;
	}

	private JScrollPane getJScrollPane() {
		if (jScrollPane == null) {
			jScrollPane = new JScrollPane();
			jScrollPane.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 11));
			jScrollPane.setHorizontalScrollBarPolicy(javax.swing.JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
			jScrollPane.setViewportView(getResultsTable());
		}
		return jScrollPane;
	}

	private HistoryReferenceTable getResultsTable () {
		if (this.resultsTable == null) {
			this.model = new ZestResultsTableModel(COLS);
			this.resultsTable = new HistoryReferenceTable(model) {

				private static final long serialVersionUID = 557191363644673221L;

				@Override
				public HistoryReference getSelectedValue() {
					if (this.getSelectedRow() >= 0) {
						return model.getHistoryReference(resultsTable.convertRowIndexToModel(this.getSelectedRow()));
					}
					return null;
				}
			};
			this.resultsTable.setName(TABLE_NAME);
			this.resultsTable.setColumnSizes(SIZES);
			this.resultsTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		}
		return this.resultsTable;
	}
	
	protected ZestResultsTableModel getModel() {
		return model;
	}

	public boolean isSelectedMessage(Message message) {
		List<HistoryReference> hrefs = this.getResultsTable().getSelectedValues();

		if (hrefs.size() == 1) {
			try {
				return hrefs.get(0).getHttpMessage().hashCode() == message.hashCode();
			} catch (Exception e) {
				// Ignore
			}
		}
		return false;
	}

}
