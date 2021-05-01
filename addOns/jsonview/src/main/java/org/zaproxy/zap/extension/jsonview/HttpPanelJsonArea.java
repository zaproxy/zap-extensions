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
package org.zaproxy.zap.extension.jsonview;

import java.util.List;
import java.util.regex.Pattern;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.httppanel.view.syntaxhighlight.HttpPanelSyntaxHighlightTextArea;
import org.zaproxy.zap.extension.search.SearchMatch;

public class HttpPanelJsonArea extends HttpPanelSyntaxHighlightTextArea {

    private static final long serialVersionUID = 1L;

    public HttpPanelJsonArea() {
        setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JSON);
        addSyntaxStyle(
                Constant.messages.getString("http.panel.view.syntaxtext.syntax.json"),
                SyntaxConstants.SYNTAX_STYLE_JSON);
        setCodeFoldingEnabled(true);
    }

    @Override
    public void search(Pattern pattern, List<SearchMatch> list) {}

    @Override
    public void highlight(SearchMatch searchMatch) {}

    @Override
    protected CustomTokenMakerFactory getTokenMakerFactory() {
        return null;
    }
}
