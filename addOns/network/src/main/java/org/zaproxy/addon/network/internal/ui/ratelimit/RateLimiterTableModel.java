/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.ui.ratelimit;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.swing.table.AbstractTableModel;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.network.internal.ratelimit.RateLimiter;
import org.zaproxy.addon.network.internal.ratelimit.RateLimiterEntry;

@SuppressWarnings("serial")
public class RateLimiterTableModel extends AbstractTableModel {
    private static final String[] COLUMN_NAMES = {
        Constant.messages.getString("network.ui.ratelimit.status.header.group"),
        Constant.messages.getString("network.ui.ratelimit.status.header.description"),
        Constant.messages.getString("network.ui.ratelimit.status.header.requestcount"),
        Constant.messages.getString("network.ui.ratelimit.status.header.effectiverate"),
        Constant.messages.getString("network.ui.ratelimit.status.header.lastrequest")
    };

    private static final int COLUMN_COUNT = COLUMN_NAMES.length;

    private List<RateLimiterEntry> limiterEntries;

    public RateLimiterTableModel() {
        limiterEntries = new ArrayList<>();
    }

    public void update(RateLimiter limiter) {
        limiterEntries = limiter.getEntries();
        fireTableDataChanged();
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public int getColumnCount() {
        return COLUMN_COUNT;
    }

    @Override
    public int getRowCount() {
        return limiterEntries.size();
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        RateLimiterEntry entry = limiterEntries.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return entry.getKey().getKey();
            case 1:
                return entry.getKey().getRuleDescription();
            case 2:
                return entry.getRequestCount();
            case 3:
                return entry.getEffectiveRequestsPerSecond();
            case 4:
                if (entry.getLastRequestTime() == 0) {
                    return null;
                }
                return new Date(entry.getLastRequestTime());
            default:
                return null;
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 2:
                return Long.class;
            case 3:
                return BigDecimal.class;
            case 4:
                return Date.class;
            default:
                return String.class;
        }
    }
}
