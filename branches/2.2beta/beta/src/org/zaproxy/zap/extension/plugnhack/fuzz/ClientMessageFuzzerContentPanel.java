/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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
package org.zaproxy.zap.extension.plugnhack.fuzz;

import java.awt.GridBagLayout;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;

import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.fuzz.FuzzResult;
import org.zaproxy.zap.extension.fuzz.FuzzerContentPanel;
import org.zaproxy.zap.extension.plugnhack.ClientMessage;
import org.zaproxy.zap.extension.plugnhack.MessageListTableModel;
import org.zaproxy.zap.view.LayoutHelper;

public class ClientMessageFuzzerContentPanel implements FuzzerContentPanel {

	private static final Logger logger = Logger.getLogger(ClientMessageFuzzerContentPanel.class);

	private JPanel panel = null;

	private MessageListTableModel msgTableModel = null;
	private JTable msgTable = null;

	public ClientMessageFuzzerContentPanel() {
		
		this.msgTable = new JTable(getMessageModel ());
		//this.msgTable.setName(CLIENTS_MESSAGE_TABLE_NAME);
		this.setMessageTableColumnSizes();
		//this.msgTable.setFont(new Font("Dialog", Font.PLAIN, 11));
		this.msgTable.setDoubleBuffered(true);
		this.msgTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		panel = new JPanel();
		panel.setLayout(new GridBagLayout());
		panel.add(this.msgTable, LayoutHelper.getGBC(0, 0, 1, 1.0D, 10.D));
	}
	
	private MessageListTableModel getMessageModel () {
		if (this.msgTableModel == null) {
			this.msgTableModel = new MessageListTableModel();
		}
		return this.msgTableModel;
	}

	private void setMessageTableColumnSizes() {
		
		msgTable.getColumnModel().getColumn(0).setMinWidth(50);
		msgTable.getColumnModel().getColumn(0).setMaxWidth(200);
		msgTable.getColumnModel().getColumn(0).setPreferredWidth(100);	// Received
		
		msgTable.getColumnModel().getColumn(1).setMinWidth(20);
		msgTable.getColumnModel().getColumn(1).setMaxWidth(20);
		msgTable.getColumnModel().getColumn(1).setPreferredWidth(20);	// Changed icon
		
		msgTable.getColumnModel().getColumn(2).setMinWidth(50);
		msgTable.getColumnModel().getColumn(2).setMaxWidth(200);
		msgTable.getColumnModel().getColumn(2).setPreferredWidth(100);	// Client
		
		msgTable.getColumnModel().getColumn(3).setMinWidth(100);
		msgTable.getColumnModel().getColumn(3).setMaxWidth(200);
		msgTable.getColumnModel().getColumn(3).setPreferredWidth(200);	// Type
		
		msgTable.getColumnModel().getColumn(4).setMinWidth(100);
		//msgTable.getColumnModel().getColumn(4).setMaxWidth(200);
		msgTable.getColumnModel().getColumn(4).setPreferredWidth(400);	// Data
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	@Override
	public void clear() {
		this.getMessageModel().removeAllElements();

	}

	@Override
	public void addFuzzResult(FuzzResult fuzzResult) {
		this.getMessageModel().addClientMessage(((ClientMessageFuzzResult)fuzzResult).getMessage());
	}

	public void flagOracleInvoked(int id) {
		logger.debug("Oracle: " + id);
		for (int row = 0; row < this.getMessageModel().getRowCount(); row++) {
			ClientMessage msg = this.getMessageModel().getClientMessageAtRow(row);
			if (msg.getData().indexOf("xss(" + id + ")") >= 0) {
				// Found the attack!
				// Flag in the fuzzer window
				msg.setState(ClientMessage.State.oraclehit);
				this.getMessageModel().clientMessageChanged(msg);
				return;
			}
		}
		logger.debug("Oracle not found: " + id);
	}

}
