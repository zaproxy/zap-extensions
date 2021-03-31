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

import java.awt.Component;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JLabel;
import javax.swing.SortOrder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableModel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jdesktop.swingx.decorator.AbstractHighlighter;
import org.jdesktop.swingx.decorator.ComponentAdapter;
import org.jdesktop.swingx.renderer.IconAware;
import org.jdesktop.swingx.table.TableColumnExt;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.extension.search.SearchMatch;
import org.zaproxy.zap.view.table.HistoryReferencesTable;

public class HttpFuzzerResultsTable extends HistoryReferencesTable {

    private static final long serialVersionUID = -1910120966638329368L;

    private static final Logger LOGGER = LogManager.getLogger(HttpFuzzerResultsTable.class);

    private final FuzzResultStateHighlighter fuzzResultStateHighlighter;

    public HttpFuzzerResultsTable(String name, HttpFuzzerResultsTableModel resultsModel) {
        super(resultsModel, false);

        setName(name);

        getSelectionModel().addListSelectionListener(new DisplayMessageOnSelectionValueChange());

        setAutoCreateColumnsFromModel(false);

        getColumnExt(Constant.messages.getString("view.href.table.header.timestamp.request"))
                .setVisible(false);
        getColumnExt(Constant.messages.getString("view.href.table.header.method"))
                .setVisible(false);
        getColumnExt(Constant.messages.getString("view.href.table.header.url")).setVisible(false);
        getColumnExt(Constant.messages.getString("view.href.table.header.size.requestheader"))
                .setVisible(false);
        getColumnExt(Constant.messages.getString("view.href.table.header.size.requestbody"))
                .setVisible(false);

        TableColumnExt stateColumn =
                getColumnExt(
                        Constant.messages.getString(
                                "fuzz.httpfuzzer.results.tab.messages.table.header.state"));
        fuzzResultStateHighlighter = new FuzzResultStateHighlighter(stateColumn.getModelIndex());
        stateColumn.addHighlighter(fuzzResultStateHighlighter);

        // Sort on task ID
        setSortOrder(0, SortOrder.ASCENDING);
    }

    public String getCustomStateValue(Map<String, Object> customState) {
        for (HttpFuzzerResultStateHighlighter highlighter :
                fuzzResultStateHighlighter.highlighters) {
            if (highlighter.isHighlighted(customState)) {
                return highlighter.getLabel();
            }
        }
        return "";
    }

    public void addFuzzResultStateHighlighter(HttpFuzzerResultStateHighlighter highlighter) {
        fuzzResultStateHighlighter.addStateHighlighter(highlighter);
    }

    public void removeFuzzResultStateHighlighter(HttpFuzzerResultStateHighlighter highlighter) {
        fuzzResultStateHighlighter.removeStateHighlighter(highlighter);
    }

    @Override
    public void setModel(TableModel dataModel) {
        // Keep the same column sorted when model is changed
        int sortedcolumnIndex = getSortedColumnIndex();
        SortOrder sortOrder = getSortOrder(sortedcolumnIndex);
        super.setModel(dataModel);
        if (sortedcolumnIndex != -1) {
            setSortOrder(sortedcolumnIndex, sortOrder);
        }
    }

    protected class DisplayMessageOnSelectionValueChange implements ListSelectionListener {

        @Override
        public void valueChanged(final ListSelectionEvent evt) {
            if (!evt.getValueIsAdjusting()) {
                HistoryReference hRef = getSelectedHistoryReference();
                if (hRef == null) {
                    return;
                }

                try {
                    HttpMessage httpMessage = hRef.getHttpMessage();
                    displayMessage(httpMessage);

                    for (Object payload :
                            ((HttpFuzzerResultsTableModel) getModel())
                                    .getPayloads(hRef.getHistoryId())) {
                        String strPayload = payload.toString();
                        if (strPayload.isEmpty()) {
                            continue;
                        }

                        int startIndex =
                                httpMessage.getResponseBody().toString().indexOf(strPayload);
                        if (startIndex >= 0) {
                            // Found the exact pattern - highlight it
                            SearchMatch sm =
                                    new SearchMatch(
                                            httpMessage,
                                            SearchMatch.Location.RESPONSE_BODY,
                                            startIndex,
                                            startIndex + strPayload.length());
                            View.getSingleton().getResponsePanel().setTabFocus();
                            View.getSingleton().getResponsePanel().requestFocusInWindow();
                            View.getSingleton().getResponsePanel().highlightBody(sm);
                        }
                    }
                    HttpFuzzerResultsTable.this.requestFocusInWindow();

                } catch (HttpMalformedHeaderException | DatabaseException e) {
                    LOGGER.error(e.getMessage(), e);
                }
            }
        }
    }

    private static class FuzzResultStateHighlighter extends AbstractHighlighter {

        private final List<HttpFuzzerResultStateHighlighter> highlighters;
        private final int columnIndex;

        public FuzzResultStateHighlighter(int columnIndex) {
            this.highlighters = new ArrayList<>();
            this.columnIndex = columnIndex;
        }

        @Override
        protected Component doHighlight(Component component, ComponentAdapter adapter) {
            @SuppressWarnings("unchecked")
            Map<String, Object> data =
                    new HashMap<>((Map<String, Object>) adapter.getValue(columnIndex));

            StringBuilder labelBuilder = new StringBuilder();
            boolean iconSet = false;
            for (HttpFuzzerResultStateHighlighter highlighter : highlighters) {
                if (highlighter.isHighlighted(data)) {
                    if (!iconSet) {
                        if (component instanceof IconAware) {
                            ((IconAware) component).setIcon(highlighter.getIcon());
                            iconSet = true;
                        } else if (component instanceof JLabel) {
                            ((JLabel) component).setIcon(highlighter.getIcon());
                            iconSet = true;
                        }
                    }

                    if (component instanceof JLabel) {
                        append(labelBuilder, highlighter.getLabel());
                    }
                    highlighter.removeState(data);
                }
            }

            for (Object value : data.values()) {
                append(labelBuilder, value);
            }

            if (!iconSet) {
                if (component instanceof IconAware) {
                    ((IconAware) component).setIcon(null);
                } else if (component instanceof JLabel) {
                    ((JLabel) component).setIcon(null);
                }
            }

            if (component instanceof JLabel) {
                ((JLabel) component).setText(labelBuilder.toString());
            }

            return component;
        }

        private static void append(StringBuilder strBuilder, Object value) {
            if (strBuilder.length() > 0) {
                strBuilder.append("; ");
            }
            strBuilder.append(value);
        }

        public void addStateHighlighter(HttpFuzzerResultStateHighlighter highlighter) {
            highlighters.add(highlighter);
        }

        public void removeStateHighlighter(HttpFuzzerResultStateHighlighter highlighter) {
            highlighters.remove(highlighter);
        }

        /**
         * {@inheritDoc}
         *
         * <p>Overridden to return true if the component is of type IconAware or of type JLabel,
         * false otherwise.
         *
         * <p>Note: special casing JLabel is for backward compatibility - application highlighting
         * code which doesn't use the Swingx renderers would stop working otherwise.
         */
        // Method/JavaDoc copied from
        // org.jdesktop.swingx.decorator.IconHighlighter#canHighlight(Component, ComponentAdapter)
        @Override
        protected boolean canHighlight(final Component component, final ComponentAdapter adapter) {
            return component instanceof IconAware || component instanceof JLabel;
        }
    }
}
