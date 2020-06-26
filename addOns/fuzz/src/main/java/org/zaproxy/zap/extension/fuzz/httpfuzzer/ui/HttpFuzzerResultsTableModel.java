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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.ui;

import java.awt.EventQueue;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.ExtensionHttpFuzzer;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzResult;
import org.zaproxy.zap.extension.search.ExtensionSearch;
import org.zaproxy.zap.extension.search.SearchMatch;
import org.zaproxy.zap.extension.search.SearchResult;
import org.zaproxy.zap.view.table.AbstractCustomColumnHistoryReferencesTableModel;
import org.zaproxy.zap.view.table.AbstractHistoryReferencesTableEntry;
import org.zaproxy.zap.view.table.DefaultHistoryReferencesTableEntry;

public class HttpFuzzerResultsTableModel
        extends AbstractCustomColumnHistoryReferencesTableModel<
                HttpFuzzerResultsTableModel.FuzzResultTableEntry> {

    private static final long serialVersionUID = -7711293371478878302L;

    private static final Logger logger = Logger.getLogger(HttpFuzzerResultsTableModel.class);

    private static final Column[] COLUMNS =
            new Column[] {
                Column.CUSTOM,
                Column.CUSTOM,
                Column.REQUEST_TIMESTAMP,
                Column.METHOD,
                Column.URL,
                Column.STATUS_CODE,
                Column.STATUS_REASON,
                Column.RTT,
                Column.SIZE_REQUEST_HEADER,
                Column.SIZE_REQUEST_BODY,
                Column.SIZE_RESPONSE_HEADER,
                Column.SIZE_RESPONSE_BODY,
                Column.HIGHEST_ALERT,
                Column.CUSTOM,
                Column.CUSTOM
            };

    private static final String[] CUSTOM_COLUMN_NAMES = {
        Constant.messages.getString("fuzz.httpfuzzer.results.tab.messages.table.header.taskId"),
        Constant.messages.getString("fuzz.httpfuzzer.results.tab.messages.table.header.type"),
        Constant.messages.getString("fuzz.httpfuzzer.results.tab.messages.table.header.state"),
        Constant.messages.getString("fuzz.httpfuzzer.results.tab.messages.table.header.payloads")
    };

    private List<FuzzResultTableEntry> results;
    private Map<Integer, Integer> idsToRows;

    public HttpFuzzerResultsTableModel() {
        super(COLUMNS);

        results = new ArrayList<>();
        idsToRows = new HashMap<>();
    }

    public void addResult(final HttpFuzzResult result) {
        try {
            final HistoryReference href =
                    result.getHttpMessage().getHistoryRef() != null
                            ? result.getHttpMessage().getHistoryRef()
                            : new HistoryReference(
                                    Model.getSingleton().getSession(),
                                    HistoryReference.TYPE_FUZZER_TEMPORARY,
                                    result.getHttpMessage());

            EventQueue.invokeLater(
                    new Runnable() {

                        @Override
                        public void run() {
                            final int row = results.size();
                            idsToRows.put(
                                    Integer.valueOf(href.getHistoryId()), Integer.valueOf(row));
                            results.add(
                                    new FuzzResultTableEntry(
                                            href,
                                            result.getTaskId(),
                                            result.getType(),
                                            result.getCustomStates(),
                                            result.getPayloads()));
                            fireTableRowsInserted(row, row);
                        }
                    });
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            logger.error("Failed to persist (and show) the message:", e);
        }
    }

    @Override
    public void addEntry(FuzzResultTableEntry entry) {}

    @Override
    public void refreshEntryRow(int historyReferenceId) {}

    @Override
    public void removeEntry(int historyReferenceId) {}

    @Override
    public FuzzResultTableEntry getEntry(int rowIndex) {
        return results.get(rowIndex);
    }

    @Override
    public FuzzResultTableEntry getEntryWithHistoryId(int historyReferenceId) {
        return null;
    }

    @Override
    public int getEntryRowIndex(int historyReferenceId) {
        return -1;
    }

    @Override
    public void clear() {
        results = new ArrayList<>();
        idsToRows = new HashMap<>();
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return results.size();
    }

    @Override
    protected Class<?> getColumnClass(Column column) {
        return AbstractHistoryReferencesTableEntry.getColumnClass(column);
    }

    @Override
    protected Object getPrototypeValue(Column column) {
        return AbstractHistoryReferencesTableEntry.getPrototypeValue(column);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (columnIndex == -1) {
            return getEntry(rowIndex);
        }
        return super.getValueAt(rowIndex, columnIndex);
    }

    @Override
    protected Object getCustomValueAt(FuzzResultTableEntry entry, int columnIndex) {
        switch (getCustomColumnIndex(columnIndex)) {
            case 0:
                return Long.valueOf(entry.getTaskId());
            case 1:
                return entry.getType();
            case 2:
                return entry.getCustomStates();
            case 3:
                return StringUtils.join(entry.getPayloads(), ", ");
        }
        return null;
    }

    @Override
    protected String getCustomColumnName(int columnIndex) {
        return CUSTOM_COLUMN_NAMES[getCustomColumnIndex(columnIndex)];
    }

    @Override
    protected Class<?> getCustomColumnClass(int columnIndex) {
        switch (getCustomColumnIndex(columnIndex)) {
            case 0:
                return Long.class;
            case 1:
                return String.class;
            case 2:
                return Map.class;
            case 3:
                return String.class;
        }
        return null;
    }

    @Override
    protected Object getCustomPrototypeValue(int columnIndex) {
        switch (getCustomColumnIndex(columnIndex)) {
            case 0:
                return Long.valueOf(10000);
            case 1:
                return "Fuzzed";
            case 2:
                return "State description";
            case 3:
                return Collections.emptyList();
        }
        return null;
    }

    public List<Object> getPayloads(int historyReferenceId) {
        Integer row = idsToRows.get(Integer.valueOf(historyReferenceId));
        if (row == null) {
            return Collections.emptyList();
        }

        return results.get(row.intValue()).getPayloads();
    }

    public List<String> getHeaders() {
        List<String> headers = new ArrayList<>(getColumnCount());
        for (int i = 0; i < getColumnCount(); i++) {
            headers.add(getColumnName(i));
        }
        return headers;
    }

    static class FuzzResultTableEntry extends DefaultHistoryReferencesTableEntry {

        private final long taskId;
        private final String type;
        private final Map<String, Object> customStates;
        private final List<Object> payloads;

        public FuzzResultTableEntry(
                HistoryReference historyReference,
                long taskId,
                String type,
                Map<String, Object> customStates,
                List<Object> payloads) {
            super(historyReference, COLUMNS);
            this.taskId = taskId;
            this.type = type;
            this.customStates = customStates;
            this.payloads = payloads;
        }

        public long getTaskId() {
            return taskId;
        }

        public String getType() {
            return type;
        }

        public List<Object> getPayloads() {
            return payloads;
        }

        public Map<String, Object> getCustomStates() {
            return customStates;
        }

        public List<Object> getValuesOfHeaders() {
            List<Object> values = new ArrayList<>();
            values.add(getTaskId());
            values.add(getType());
            values.add(getRequestTimestamp());
            values.add(getMethod());
            values.add(getUri());
            values.add(getStatusCode());
            values.add(getReason());
            values.add(getRtt());
            values.add(getRequestHeaderSize());
            values.add(getRequestBodySize());
            values.add(getResponseHeaderSize());
            values.add(getResponseBodySize());
            values.add(getHighestAlert());
            values.add(getPayloads());
            return values;
        }
    }

    public List<SearchResult> search(Pattern pattern, boolean inverse) {
        return search(pattern, inverse, -1);
    }

    public List<SearchResult> search(Pattern pattern, boolean inverse, int max) {
        List<SearchResult> searchResults = new ArrayList<>();

        Matcher matcher;
        int rowCount = getRowCount();
        int matches = 0;
        // Start at 1 to skip the original message
        for (int i = 1; i < rowCount; i++) {
            if (max > 0 && matches >= max) {
                break;
            }

            HistoryReference historyReference = getEntry(i).getHistoryReference();
            try {
                HttpMessage msg = historyReference.getHttpMessage();
                if (inverse) {
                    // Check for no matches in either Response Header or Body
                    if (!pattern.matcher(msg.getResponseHeader().toString()).find()
                            && !pattern.matcher(msg.getResponseBody().toString()).find()) {
                        searchResults.add(
                                createSearchResult(
                                        pattern.toString(),
                                        "",
                                        msg,
                                        SearchMatch.Location.RESPONSE_HEAD,
                                        0,
                                        0));
                        matches++;
                    }
                } else {
                    // Response header
                    matcher = pattern.matcher(msg.getResponseHeader().toString());
                    while (matcher.find() && !(max > 0 && matches >= max)) {
                        searchResults.add(
                                createSearchResult(
                                        pattern.toString(),
                                        matcher.group(),
                                        msg,
                                        SearchMatch.Location.RESPONSE_HEAD,
                                        matcher.start(),
                                        matcher.end()));
                        matches++;
                    }
                    // Response body
                    matcher = pattern.matcher(msg.getResponseBody().toString());
                    while (matcher.find() && !(max > 0 && matches >= max)) {
                        searchResults.add(
                                createSearchResult(
                                        pattern.toString(),
                                        matcher.group(),
                                        msg,
                                        SearchMatch.Location.RESPONSE_BODY,
                                        matcher.start(),
                                        matcher.end()));
                        matches++;
                    }
                }
            } catch (HttpMalformedHeaderException | DatabaseException e) {
                logger.error(e.getMessage(), e);
            }
        }
        return searchResults;
    }

    protected SearchResult createSearchResult(
            String regex,
            String match,
            HttpMessage msg,
            SearchMatch.Location location,
            int start,
            int end) {
        return new SearchResult(
                ExtensionSearch.Type.Custom,
                ExtensionHttpFuzzer.HttpFuzzerSearcher.SEARCHER_NAME,
                regex,
                match,
                new SearchMatch(msg, location, start, end));
    }
}
