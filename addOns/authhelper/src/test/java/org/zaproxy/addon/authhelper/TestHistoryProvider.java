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
package org.zaproxy.addon.authhelper;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.IntStream;
import lombok.Getter;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class TestHistoryProvider extends HistoryProvider {
    @Getter protected List<HttpMessage> history;

    public TestHistoryProvider() {
        history = new ArrayList<>();
    }

    public TestHistoryProvider(List<HttpMessage> msgs) {
        this.history = msgs;
    }

    @Override
    public void addAuthMessageToHistory(HttpMessage msg) {
        history.add(msg);
        int id = history.size();
        HistoryReference href =
                mock(HistoryReference.class, withSettings().strictness(Strictness.LENIENT));
        given(href.getHistoryId()).willReturn(id);
        msg.setHistoryRef(href);
    }

    @Override
    public HttpMessage getHttpMessage(int historyId)
            throws HttpMalformedHeaderException, DatabaseException {
        return history.get(historyId - 1);
    }

    @Override
    public int getLastHistoryId() {
        return history.size();
    }

    @Override
    List<Integer> getMessageIds(int first, int last, String value) {
        // Ordered high to low to mimic the query being DESC
        return IntStream.rangeClosed(1, history.size())
                .boxed()
                .sorted(Collections.reverseOrder())
                .toList();
    }
}
