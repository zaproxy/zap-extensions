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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.tagcreator;

import java.util.Map;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.ui.HttpFuzzerResultStateHighlighter;
import org.zaproxy.zap.view.table.decorator.NoteTableCellItemIconHighlighter;

public class HttpFuzzerMessageProcessorTagStateHighlighter
        implements HttpFuzzerResultStateHighlighter {

    private static final Icon REFLECTED_ICON =
            new ImageIcon(
                    NoteTableCellItemIconHighlighter.class.getResource(
                            "/resource/icon/16/073.png"));
    private static final String TAG_CREATOR_TEXT_STATE_KEY =
            HttpFuzzerMessageProcessorTagCreator.TAG_CREATOR_TEXT_STATE_KEY;
    private String tagsAsText;

    @Override
    public boolean isHighlighted(Map<String, Object> data) {
        tagsAsText = getTagsAsTextFromCustomState(data);
        return tagsAsText.length() > 0;
    }

    private String getTagsAsTextFromCustomState(Map<String, Object> state) {
        if (state.containsKey(TAG_CREATOR_TEXT_STATE_KEY)) {
            return (String) state.get(TAG_CREATOR_TEXT_STATE_KEY);
        }
        return "";
    }

    @Override
    public Icon getIcon() {
        return REFLECTED_ICON;
    }

    @Override
    public String getLabel() {
        return tagsAsText;
    }

    @Override
    public void removeState(Map<String, Object> data) {
        data.remove(TAG_CREATOR_TEXT_STATE_KEY);
        data.remove(HttpFuzzerMessageProcessorTagCreator.TAG_CREATOR_LIST_STATE_KEY);
    }
}
