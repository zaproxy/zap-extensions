/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.authenticationhelper.statusscan;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.view.table.AbstractCustomColumnHistoryReferencesTableModel;
import org.zaproxy.zap.view.table.AbstractHistoryReferencesTableEntry;
import org.zaproxy.zap.view.table.AlertRiskTableCellItem;
import org.zaproxy.zap.view.table.DefaultHistoryReferencesTableEntry;

public class AuthenticationStatusTableModel
        extends AbstractCustomColumnHistoryReferencesTableModel<AuthenticationStatusTableEntry> {

    private static final long serialVersionUID = -3849329517361708409L;

    public static final Icon FAILED_STATUS_ICON;
    public static final Icon SUCCESSFULL_STATUS_ICON;
    public static final Icon CONFLICTING_STATUS_ICON;
    public static final Icon UNKNOWN_STATUS_ICON;

    public static final Icon FOUND_ICON;
    public static final Icon NOT_FOUND_ICON;
    public static final Icon NOT_DEFINED_ICON;
    public static final Icon COULD_NOT_VERIFY_ICON;

    static final Column[] COLUMNS =
            new Column[] {
                Column.URL,
                Column.CUSTOM,
                Column.CUSTOM,
                Column.CUSTOM,
                Column.HREF_ID,
                Column.REQUEST_TIMESTAMP,
                Column.RESPONSE_TIMESTAMP,
                Column.METHOD,
                Column.STATUS_CODE,
                Column.STATUS_REASON,
                Column.RTT,
                Column.SIZE_REQUEST_HEADER,
                Column.SIZE_REQUEST_BODY,
                Column.SIZE_RESPONSE_HEADER,
                Column.SIZE_RESPONSE_BODY,
                Column.HIGHEST_ALERT,
                Column.TAGS
            };

    private static final String[] CUSTOM_COLUMN_NAMES = {
        Constant.messages.getString(
                "authenticationhelper.table.authenticationStatus.header.status"),
        Constant.messages.getString(
                "authenticationhelper.table.authenticationStatus.header.loggedInIndicator"),
        Constant.messages.getString(
                "authenticationhelper.table.authenticationStatus.header.loggedOutIndicator")
    };

    private List<AuthenticationStatusTableEntry> authenticationStatusTableEntries;
    private Map<Integer, Integer> hrefIdsToRowIndexes;

    static {
        FAILED_STATUS_ICON =
                new ImageIcon(
                        AuthenticationStatusTableModel.class.getResource(
                                "/org/zaproxy/zap/extension/authenticationhelper/resources/help/contents/images/cross-circle.png"));
        SUCCESSFULL_STATUS_ICON =
                new ImageIcon(
                        AuthenticationStatusTableModel.class.getResource(
                                "/org/zaproxy/zap/extension/authenticationhelper/resources/help/contents/images/tick-circle.png"));
        CONFLICTING_STATUS_ICON =
                new ImageIcon(
                        AuthenticationStatusTableModel.class.getResource(
                                "/org/zaproxy/zap/extension/authenticationhelper/resources/help/contents/images/exclamation-circle.png"));
        UNKNOWN_STATUS_ICON =
                new ImageIcon(
                        AuthenticationStatusTableModel.class.getResource(
                                "/org/zaproxy/zap/extension/authenticationhelper/resources/help/contents/images/question-white.png"));

        FOUND_ICON =
                new ImageIcon(
                        AuthenticationStatusTableModel.class.getResource(
                                "/org/zaproxy/zap/extension/authenticationhelper/resources/help/contents/images/tick.png"));
        NOT_FOUND_ICON =
                new ImageIcon(
                        AuthenticationStatusTableModel.class.getResource(
                                "/org/zaproxy/zap/extension/authenticationhelper/resources/help/contents/images/cross.png"));
        NOT_DEFINED_ICON =
                new ImageIcon(
                        AuthenticationStatusTableModel.class.getResource(
                                "/org/zaproxy/zap/extension/authenticationhelper/resources/help/contents/images/ash-circle.png"));
        COULD_NOT_VERIFY_ICON =
                new ImageIcon(
                        AuthenticationStatusTableModel.class.getResource(
                                "/org/zaproxy/zap/extension/authenticationhelper/resources/help/contents/images/red-circle.png"));
    }

    public AuthenticationStatusTableModel() {
        super(COLUMNS);
        authenticationStatusTableEntries = new ArrayList<>();
        hrefIdsToRowIndexes = new HashMap<>();
    }

    @Override
    public void addEntry(final AuthenticationStatusTableEntry entry) {
        final int newRowIndex = authenticationStatusTableEntries.size();
        hrefIdsToRowIndexes.put(Integer.valueOf(entry.getHistoryId()), newRowIndex);
        authenticationStatusTableEntries.add(entry);
        fireTableRowsInserted(newRowIndex, newRowIndex);
    }

    @Override
    public void refreshEntryRow(int historyReferenceId) {
        final DefaultHistoryReferencesTableEntry entry = getEntryWithHistoryId(historyReferenceId);

        if (entry != null) {
            int rowIndex = getEntryRowIndex(historyReferenceId);
            getEntryWithHistoryId(historyReferenceId).refreshCachedValues();

            fireTableRowsUpdated(rowIndex, rowIndex);
        }
    }

    @Override
    public void removeEntry(int historyReferenceId) {
        // Nothing to do, the entries are not removed.
    }

    @Override
    public AuthenticationStatusTableEntry getEntry(int rowIndex) {
        return authenticationStatusTableEntries.get(rowIndex);
    }

    @Override
    public AuthenticationStatusTableEntry getEntryWithHistoryId(int historyReferenceId) {
        final int rowIndex = getEntryRowIndex(historyReferenceId);
        if (rowIndex != -1) {
            return authenticationStatusTableEntries.get(rowIndex);
        }
        return null;
    }

    @Override
    public int getEntryRowIndex(int historyReferenceId) {
        final Integer rowIndex = hrefIdsToRowIndexes.get(historyReferenceId);
        if (rowIndex != null) {
            return rowIndex;
        }
        return -1;
    }

    @Override
    public void clear() {
        authenticationStatusTableEntries = new ArrayList<>();
        hrefIdsToRowIndexes = new HashMap<>();
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return authenticationStatusTableEntries.size();
    }

    @Override
    protected Object getCustomValueAt(AuthenticationStatusTableEntry entry, int columnIndex) {
        int customColumnIndex = getCustomColumnIndex(columnIndex);
        if (customColumnIndex == 0) {
            return resolveAuthenticationStatusIcon(entry.getAuthenticationStatus());
        }
        if (customColumnIndex == 1) {
            return resolveIndicatorStatusIcon(entry.getLoggedInIndicatorStatus());
        }
        if (customColumnIndex == 2) {
            return resolveIndicatorStatusIcon(entry.getLoggedOutIndicatorStatus());
        }

        throw new IllegalArgumentException(
                "Custom column index should be either 0, 1 or 2, but got " + customColumnIndex);
    }

    private Icon resolveAuthenticationStatusIcon(
            AuthenticationStatusTableEntry.AuthenticationStatus authenticationStatus) {
        switch (authenticationStatus) {
            case SUCCESSFULL:
                return SUCCESSFULL_STATUS_ICON;
            case FAILED:
                return FAILED_STATUS_ICON;
            case CONFLICTING:
                return CONFLICTING_STATUS_ICON;
            case UNKNOWN:
                return UNKNOWN_STATUS_ICON;
            default:
                throw new IllegalArgumentException();
        }
    }

    private Icon resolveIndicatorStatusIcon(
            AuthenticationStatusScanner.IndicatorStatus indicatorStatus) {
        switch (indicatorStatus) {
            case FOUND:
                return FOUND_ICON;
            case NOT_FOUND:
                return NOT_FOUND_ICON;
            case NOT_DEFINED:
                return NOT_DEFINED_ICON;
            case COULD_NOT_VERIFY:
                return COULD_NOT_VERIFY_ICON;
            default:
                throw new IllegalArgumentException();
        }
    }

    @Override
    protected String getCustomColumnName(int columnIndex) {
        return CUSTOM_COLUMN_NAMES[getCustomColumnIndex(columnIndex)];
    }

    @Override
    protected Class<?> getColumnClass(Column column) {
        switch (column) {
            case HREF_ID:
                return Integer.class;
            case REQUEST_TIMESTAMP:
                return Date.class;
            case RESPONSE_TIMESTAMP:
                return Date.class;
            case HREF_TYPE:
                return Integer.class;
            case METHOD:
                return String.class;
            case URL:
                return String.class;
            case STATUS_CODE:
                return Integer.class;
            case STATUS_REASON:
                return String.class;
            case RTT:
                return Integer.class;
            case SIZE_MESSAGE:
            case SIZE_REQUEST_HEADER:
            case SIZE_REQUEST_BODY:
            case SIZE_RESPONSE_HEADER:
            case SIZE_RESPONSE_BODY:
                return Integer.class;
            case SESSION_ID:
                return Long.class;
            case HIGHEST_ALERT:
                return AlertRiskTableCellItem.class;
            case NOTE:
                return Boolean.class;
            case TAGS:
                return String.class;
            case CUSTOM:
                return Icon.class;
            default:
                return String.class;
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (columnIndex == -1) {
            return getEntry(rowIndex);
        }
        return super.getValueAt(rowIndex, columnIndex);
    }

    @Override
    protected Class<?> getCustomColumnClass(int columnIndex) {
        return Icon.class;
    }

    @Override
    protected Object getPrototypeValue(Column column) {
        return AbstractHistoryReferencesTableEntry.getPrototypeValue(column);
    }

    @Override
    protected Object getCustomPrototypeValue(int columnIndex) {
        int customColumnIndex = getCustomColumnIndex(columnIndex);
        if (customColumnIndex == 0) {
            return FAILED_STATUS_ICON;
        }

        if (customColumnIndex == 1 || customColumnIndex == 2) {
            return COULD_NOT_VERIFY_ICON;
        }
        throw new IllegalArgumentException(
                "Custom column index should be either 0, 1 or 2, but got " + columnIndex);
    }

    public void removeHistoryReference(HistoryReference historyReference) {
        if (historyReference == null) {
            return;
        }
        removeEntry(historyReference.getHistoryId());
    }
}
