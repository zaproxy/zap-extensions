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
package org.zaproxy.zap.extension.accessControl.view;

import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.extension.accessControl.view.AccessControlResultsTableModel.AccessControlResultsTableEntry;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.view.table.AbstractCustomColumnHistoryReferencesTableModel;
import org.zaproxy.zap.view.table.AbstractHistoryReferencesTableEntry;

public class AccessControlResultsTableModel extends
		AbstractCustomColumnHistoryReferencesTableModel<AccessControlResultsTableEntry> {

	private static final long serialVersionUID = -272409439940285996L;

	private static final short COLUMN_INDEX_USER = 4;
	private static final short COLUMN_INDEX_AUTHORIZED = 5;
	private static final short COLUMN_INDEX_ACCESS_RULE = 6;
	private static final short COLUMN_INDEX_RESULT = 7;

	private static final String UNAUTHENTICATED_USER_NAME = Constant.messages
			.getString("accessControl.scanOptions.unauthenticatedUser");
	private static final String COLUMN_NAME_USER = Constant.messages
			.getString("accessControl.results.table.header.user");
	private static final String COLUMN_NAME_AUTHORIZED = Constant.messages
			.getString("accessControl.results.table.header.authorized");
	private static final String COLUMN_NAME_ACCESS_RULE = Constant.messages
			.getString("accessControl.results.table.header.rule");
	private static final String COLUMN_NAME_RESULT = Constant.messages
			.getString("accessControl.results.table.header.result");

	private List<AccessControlResultsTableEntry> entries;

	public AccessControlResultsTableModel() {
		super(new Column[] { Column.HREF_ID, Column.METHOD, Column.URL, Column.STATUS_CODE, Column.CUSTOM,
				Column.CUSTOM, Column.CUSTOM, Column.CUSTOM });
		this.entries = new ArrayList<>();
	}

	@Override
	public void addEntry(AccessControlResultsTableEntry entry) {
		entries.add(entry);
		fireTableRowsInserted(entries.size() - 1, entries.size() - 1);
	}

	public void addEntry(HistoryReference historyReference, User user, boolean requestAuthorized,
			String accessRule, String result) {
		addEntry(new AccessControlResultsTableEntry(historyReference, user, requestAuthorized, result,
				accessRule));
	}

	@Override
	public void refreshEntryRow(int historyReferenceId) {
		// Nothing to refresh
		Logger.getLogger(getClass()).warn("'Refresh' should not be called...");
	}

	@Override
	public void removeEntry(int historyReferenceId) {
		int index = getEntryRowIndex(historyReferenceId);
		if (index >= 0) {
			entries.remove(index);
			fireTableRowsDeleted(index, index);
		}
	}

	@Override
	public AccessControlResultsTableEntry getEntry(int rowIndex) {
		return entries.get(rowIndex);
	}

	@Override
	public AccessControlResultsTableEntry getEntryWithHistoryId(int historyReferenceId) {
		return entries.get(getEntryRowIndex(historyReferenceId));
	}

	@Override
	public int getEntryRowIndex(int historyReferenceId) {
		Logger.getLogger(getClass()).warn("Non optimal implemented method should not be called...");
		for (int i = 0; i < entries.size(); i++)
			if (entries.get(i).getHistoryId() == historyReferenceId)
				return i;
		return -1;
	}

	@Override
	public void clear() {
		entries = new ArrayList<>();
		fireTableDataChanged();
	}

	@Override
	public int getRowCount() {
		return entries.size();
	}

	@Override
	protected Class<?> getColumnClass(org.zaproxy.zap.view.table.HistoryReferencesTableModel.Column column) {
		return AbstractHistoryReferencesTableEntry.getColumnClass(column);
	}

	@Override
	protected Object getPrototypeValue(org.zaproxy.zap.view.table.HistoryReferencesTableModel.Column column) {
		return AbstractHistoryReferencesTableEntry.getPrototypeValue(column);
	}

	@Override
	protected Object getCustomValueAt(AccessControlResultsTableEntry entry, int columnIndex) {
		switch (columnIndex) {
		case COLUMN_INDEX_USER:
			User user = entry.getUser();
			return user == null ? UNAUTHENTICATED_USER_NAME : user.getName();
		case COLUMN_INDEX_AUTHORIZED:
			return entry.isRequestAuthorized();
		case COLUMN_INDEX_ACCESS_RULE:
			return entry.getAccessRule();
		case COLUMN_INDEX_RESULT:
			return entry.getResult();
		default:
			return null;
		}
	}

	@Override
	protected String getCustomColumnName(int columnIndex) {
		switch (columnIndex) {
		case COLUMN_INDEX_USER:
			return COLUMN_NAME_USER;
		case COLUMN_INDEX_AUTHORIZED:
			return COLUMN_NAME_AUTHORIZED;
		case COLUMN_INDEX_ACCESS_RULE:
			return COLUMN_NAME_ACCESS_RULE;
		case COLUMN_INDEX_RESULT:
			return COLUMN_NAME_RESULT;
		default:
			return "";
		}
	}

	@Override
	protected Class<?> getCustomColumnClass(int columnIndex) {
		switch (columnIndex) {
		case COLUMN_INDEX_AUTHORIZED:
			return Boolean.class;
		default:
			return String.class;
		}

	}

	@Override
	protected Object getCustomPrototypeValue(int columnIndex) {
		switch (columnIndex) {
		case COLUMN_INDEX_USER:
			return "LongUserName";
		case COLUMN_INDEX_AUTHORIZED:
			return false;
		case COLUMN_INDEX_RESULT:
			return "ERROR";
		case COLUMN_INDEX_ACCESS_RULE:
			return "ALLOW";
		default:
			return "";
		}
	}

	public static class AccessControlResultsTableEntry extends AbstractHistoryReferencesTableEntry {

		private User user;
		private boolean requestAuthorized;
		private String result;
		private String accessRule;

		public AccessControlResultsTableEntry(HistoryReference historyReference, User user,
				boolean requestAuthorized, String result, String accessRule) {
			super(historyReference);
			this.user = user;
			this.result = result;
			this.requestAuthorized = requestAuthorized;
			this.accessRule = accessRule;
		}

		@Override
		public Integer getHistoryId() {
			return getHistoryReference().getHistoryId();
		}

		@Override
		public String getMethod() {
			return getHistoryReference().getMethod();
		}

		@Override
		public String getUri() {
			return getHistoryReference().getURI().toString();
		}

		@Override
		public Integer getStatusCode() {
			return getHistoryReference().getStatusCode();
		}

		public User getUser() {
			return user;
		}

		public String getResult() {
			return result;
		}

		public String getAccessRule() {
			return accessRule;
		}

		public boolean isRequestAuthorized() {
			return requestAuthorized;
		}

	}

}
