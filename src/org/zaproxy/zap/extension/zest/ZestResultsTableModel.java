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

import java.sql.SQLException;

import javax.swing.ImageIcon;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.view.HistoryReferenceTableModel;

public class ZestResultsTableModel extends HistoryReferenceTableModel {

	private static final long serialVersionUID = 1L;

	public ZestResultsTableModel(COLUMN[] columns) {
		super(columns);
	}

	@Override
	public String getColumnName(int column) {
		COLUMN col = this.getColumn(column);
		switch (col) {
		case CUSTOM_1:	return "";
		case CUSTOM_2:	return Constant.messages.getString("zest.results.table.header.result");
		default:	return super.getColumnName(column);
		}
	}

	@Override
	public Object getValueAt(int row, int column) {
		COLUMN col = this.getColumn(column);
		switch (col) {
		case CUSTOM_1:
			ZestResultWrapper zrw = (ZestResultWrapper)this.getHistoryReference(row);
			if (zrw.getType().equals(ZestResultWrapper.Type.scanAction)) {
				return new ImageIcon(ZAP.class.getResource("/resource/icon/16/093.png"));	// Flame
			} else if (zrw.isPassed()) {
				return new ImageIcon(ZAP.class.getResource("/resource/icon/16/102.png"));	// Red cross
			} else {
				return new ImageIcon(ZAP.class.getResource("/resource/icon/16/101.png"));	// Green tick
			}
		case CUSTOM_2:	return ((ZestResultWrapper)this.getHistoryReference(row)).getMessage();
		default:	return super.getValueAt(row, column);
		}
		
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		COLUMN col = this.getColumn(columnIndex);
		switch (col) {
		case CUSTOM_1:	return ImageIcon.class;
		case CUSTOM_2:	return String.class;
		default:	return super.getColumnClass(columnIndex);
		}
	}

	public int getIndex(HttpMessage message) {
		for (int i=0; i < this.getRowCount(); i++) {
			ZestResultWrapper zrw = ((ZestResultWrapper)this.getHistoryReference(i));
			try {
				if (zrw.getHttpMessage().hashCode() == message.hashCode()) {
					return i;
				}
			} catch (HttpMalformedHeaderException | SQLException e) {
				// Ignore
			}
		}
		return -1;
	}
}
