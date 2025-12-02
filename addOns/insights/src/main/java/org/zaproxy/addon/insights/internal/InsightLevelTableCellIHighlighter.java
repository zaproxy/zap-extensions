/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.insights.internal;

import javax.swing.Icon;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.table.decorator.AbstractTableCellItemIconHighlighter;

public class InsightLevelTableCellIHighlighter extends AbstractTableCellItemIconHighlighter {

    private static final Icon[] LEVEL_ICONS = {
        DisplayUtils.getScaledIcon(Constant.HIGH_FLAG_IMAGE_URL),
        DisplayUtils.getScaledIcon(Constant.MED_FLAG_IMAGE_URL),
        DisplayUtils.getScaledIcon(Constant.LOW_FLAG_IMAGE_URL),
        DisplayUtils.getScaledIcon(Constant.INFO_FLAG_IMAGE_URL),
    };

    private static final int LEVEL_ICONS_LENGTH = LEVEL_ICONS.length;

    public InsightLevelTableCellIHighlighter(int columnIndex) {
        super(columnIndex);
    }

    @Override
    protected Icon getIcon(Object cellItem) {
        return getIcon(((Insight.Level) cellItem).ordinal());
    }

    private static Icon getIcon(int level) {
        if (level < 0 || level >= LEVEL_ICONS_LENGTH) {
            return null;
        }
        return LEVEL_ICONS[level];
    }

    @Override
    protected boolean isHighlighted(Object cellItem) {
        return true;
    }
}
