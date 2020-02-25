/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
import java.util.regex.Pattern;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.httppanel.view.text.HttpPanelTextArea;
import org.zaproxy.zap.extension.httppanel.view.text.HttpPanelTextView;
import org.zaproxy.zap.extension.plugnhack.httppanel.models.StringClientPanelViewModel;
import org.zaproxy.zap.extension.search.SearchMatch;

public class ClientPanelJsonView extends HttpPanelTextView {

    public ClientPanelJsonView(StringClientPanelViewModel model) {
        super(model);
    }

    @Override
    protected HttpPanelTextArea createHttpPanelTextArea() {
        return new ClientPanelTextArea();
    }

    @Override
    public String getCaptionName() {
        return Constant.messages.getString("plugnhack.view.pnhjson");
    }

    @Override
    public String getName() {
        return "ClientPanelJsonView";
    }

    @Override
    public int getPosition() {
        // Want it pretty low ;)
        return 100;
    }

    protected static class ClientPanelTextArea extends HttpPanelTextArea {

        private static final long serialVersionUID = 6236551060576387786L;

        @Override
        public void search(Pattern p, List<SearchMatch> matches) {}

        @Override
        public void highlight(SearchMatch sm) {}
    }
}
