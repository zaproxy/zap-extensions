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
package org.zaproxy.addon.authhelper.internal;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.authhelper.AuthUtils;
import org.zaproxy.addon.authhelper.DiagnosticDataLoader;
import org.zaproxy.addon.authhelper.HistoryProvider;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.TestUtils;

@MockitoSettings(strictness = Strictness.LENIENT)
public class ClientSideHandlerUnitTest extends TestUtils {

    private Context context;
    private ClientSideHandler csh;
    private HttpMessageHandlerContext ctx;
    private List<HttpMessage> history;
    private HistoryProvider historyProvider;

    private static final String SESSION_TOKEN1 = "1234567890123456789012345678901234567890";

    @BeforeEach
    void setUp() throws Exception {
        Session session = mock(Session.class);
        context = new Context(session, 0);
        context.addIncludeInContextRegex("https://example0.*");
        csh = new ClientSideHandler(context);
        ctx = new TestHttpMessageHandlerContext();
        history = new ArrayList<>();
        historyProvider = new TestHistoryProvider();
        csh.setHistoryProvider(historyProvider);
        AuthUtils.setHistoryProvider(historyProvider);
    }

    @Test
    void shouldAddMessageToHistory() throws Exception {
        // Given
        HttpMessage msg = new HttpMessage(new URI("https://example0/", true));
        // When
        csh.handleMessage(ctx, msg);
        // Then
        assertThat(history.size(), is(equalTo(1)));
    }

    @Test
    void shouldDetectSimpleLogin() throws Exception {
        // Given
        HttpMessage postMsg = new HttpMessage(new URI("https://example0/", true));
        postMsg.getRequestHeader().setMethod(HttpRequestHeader.POST);
        postMsg.getRequestHeader()
                .setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.FORM_URLENCODED_CONTENT_TYPE);
        postMsg.getRequestBody().setBody("user=test@example.org.com&pass=mySuperSecretPassword");
        postMsg.getResponseHeader().setHeader(HttpHeader.SET_COOKIE, "session=" + SESSION_TOKEN1);

        HttpMessage getMsg = new HttpMessage(new URI("https://www.example.com/", true));
        postMsg.getRequestHeader().setHeader(HttpHeader.COOKIE, "session=" + SESSION_TOKEN1);
        getMsg.getResponseHeader().setHeader(HttpHeader.CONTENT_TYPE, "text/html;charset=UTF-8");
        getMsg.getResponseBody().setBody("Hi test@example.org how are you today?");

        // When
        csh.handleMessage(ctx, postMsg);
        csh.handleMessage(ctx, getMsg);

        // Then
        assertThat(history.size(), is(equalTo(2)));
        assertThat(csh.getAuthMsg().getHistoryRef().getHistoryId(), is(equalTo(0)));
    }

    @Test
    void shouldDetectBodgeitLogin() throws Exception {
        // Given
        List<HttpMessage> msgs =
                DiagnosticDataLoader.loadTestData(this.getResourcePath("bodgeit.diags").toFile());

        // When
        msgs.forEach(msg -> csh.handleMessage(ctx, msg));

        // Then
        assertThat(history.size(), is(equalTo(3)));
        assertThat(csh.getAuthMsg(), is(notNullValue()));
        /* In theory this should be 1 - the POST request rather than the GET request.
         * But bodgeit sets the session token on the first GET and does not change it - it is a vulnerable
         * app after all :)
         */
        assertThat(csh.getAuthMsg().getHistoryRef().getHistoryId(), is(equalTo(0)));
    }

    class TestHistoryProvider extends HistoryProvider {
        @Override
        public void addAuthMessageToHistory(HttpMessage msg) {
            history.add(msg);
            int id = history.size() - 1;
            HistoryReference href = mock(HistoryReference.class);
            given(href.getHistoryId()).willReturn(id);
            msg.setHistoryRef(href);
        }

        @Override
        public HttpMessage getHttpMessage(int historyId)
                throws HttpMalformedHeaderException, DatabaseException {
            return history.get(historyId);
        }

        @Override
        public int getLastHistoryId() {
            return history.size() - 1;
        }
    }

    class TestHttpMessageHandlerContext implements HttpMessageHandlerContext {

        @Override
        public boolean isRecursive() {
            return false;
        }

        @Override
        public boolean isExcluded() {
            return false;
        }

        @Override
        public boolean isFromClient() {
            return false;
        }

        @Override
        public void overridden() {}

        @Override
        public void close() {}
    }
}
