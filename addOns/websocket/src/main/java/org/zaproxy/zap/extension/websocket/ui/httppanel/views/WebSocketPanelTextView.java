/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.ui.httppanel.views;

import java.util.List;
import java.util.regex.Pattern;
import org.zaproxy.zap.extension.httppanel.view.text.HttpPanelTextArea;
import org.zaproxy.zap.extension.httppanel.view.text.HttpPanelTextView;
import org.zaproxy.zap.extension.search.SearchMatch;
import org.zaproxy.zap.extension.websocket.ui.httppanel.models.StringWebSocketPanelViewModel;

public class WebSocketPanelTextView extends HttpPanelTextView {

    public WebSocketPanelTextView(StringWebSocketPanelViewModel model) {
        super(model);
    }

    @Override
    protected HttpPanelTextArea createHttpPanelTextArea() {
        return new WebSocketPanelTextArea();
    }

    protected static class WebSocketPanelTextArea extends HttpPanelTextArea {

        private static final long serialVersionUID = 6236551060576387786L;

        @Override
        public void search(Pattern p, List<SearchMatch> matches) {}

        @Override
        public void highlight(SearchMatch sm) {}
    }

    @Override
    public void setEditable(boolean editable) {
        super.setEditable(editable);
        ((StringWebSocketPanelViewModel) getModel()).setEditable(editable);
    }
}
