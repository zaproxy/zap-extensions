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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.plugnhack.httppanel.views;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.httppanel.view.syntaxhighlight.HttpPanelSyntaxHighlightTextArea;
import org.zaproxy.zap.extension.httppanel.view.syntaxhighlight.HttpPanelSyntaxHighlightTextView;
import org.zaproxy.zap.extension.plugnhack.ExtensionPlugNHack;
import org.zaproxy.zap.extension.plugnhack.httppanel.models.StringClientPanelViewModel;
import org.zaproxy.zap.extension.search.SearchMatch;

public class ClientSyntaxHighlightTextView extends HttpPanelSyntaxHighlightTextView {

    public ClientSyntaxHighlightTextView(StringClientPanelViewModel model) {
        super(model);
    }

    @Override
    protected HttpPanelSyntaxHighlightTextArea createHttpPanelTextArea() {
        return new ClientSyntaxHighlightTextArea();
    }

    protected static class ClientSyntaxHighlightTextArea extends HttpPanelSyntaxHighlightTextArea {

        private static final long serialVersionUID = -6469629120424801024L;

        private static final String CSS =
                Constant.messages.getString("http.panel.view.syntaxtext.syntax.css");
        private static final String HTML =
                Constant.messages.getString("http.panel.view.syntaxtext.syntax.html");
        private static final String JAVASCRIPT =
                Constant.messages.getString("http.panel.view.syntaxtext.syntax.javascript");
        private static final String JSON =
                Constant.messages.getString("http.panel.view.syntaxtext.syntax.json");
        private static final String XML =
                Constant.messages.getString("http.panel.view.syntaxtext.syntax.xml");

        private static ClientTokenMakerFactory tokenMakerFactory = null;

        private final ExtensionPlugNHack extension;

        public ClientSyntaxHighlightTextArea() {
            addSyntaxStyle(CSS, SyntaxConstants.SYNTAX_STYLE_CSS);
            addSyntaxStyle(HTML, SyntaxConstants.SYNTAX_STYLE_HTML);
            addSyntaxStyle(JAVASCRIPT, SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
            addSyntaxStyle(JSON, SyntaxConstants.SYNTAX_STYLE_JSON);
            addSyntaxStyle(XML, SyntaxConstants.SYNTAX_STYLE_XML);

            this.extension =
                    (ExtensionPlugNHack)
                            Control.getSingleton()
                                    .getExtensionLoader()
                                    .getExtension(ExtensionPlugNHack.NAME);
        }

        @Override
        public void search(Pattern p, List<SearchMatch> matches) {
            Matcher m = p.matcher(getText());
            while (m.find()) {
                matches.add(new SearchMatch(null, m.start(), m.end()));
            }
        }

        @Override
        public void highlight(SearchMatch sm) {
            int len = getText().length();
            if (sm.getStart() > len || sm.getEnd() > len) {
                return;
            }

            highlight(sm.getStart(), sm.getEnd());
        }

        @Override
        protected synchronized CustomTokenMakerFactory getTokenMakerFactory() {
            if (tokenMakerFactory == null) {
                tokenMakerFactory = new ClientTokenMakerFactory();
            }
            return tokenMakerFactory;
        }

        private static class ClientTokenMakerFactory extends CustomTokenMakerFactory {

            public ClientTokenMakerFactory() {
                String pkg = "org.fife.ui.rsyntaxtextarea.modes.";

                putMapping(SYNTAX_STYLE_CSS, pkg + "CSSTokenMaker");
                putMapping(SYNTAX_STYLE_HTML, pkg + "HTMLTokenMaker");
                putMapping(SYNTAX_STYLE_JAVASCRIPT, pkg + "JavaScriptTokenMaker");
                putMapping(SYNTAX_STYLE_JSON, pkg + "JsonTokenMaker");
                putMapping(SYNTAX_STYLE_XML, pkg + "XMLTokenMaker");
            }
        }
    }
}
