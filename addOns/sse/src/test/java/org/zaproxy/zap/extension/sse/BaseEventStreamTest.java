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
package org.zaproxy.zap.extension.sse;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.BeforeAll;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.utils.I18N;

abstract class BaseEventStreamTest {

    @BeforeAll
    static void beforeClass() {
        // ServerSentEvent relies on this attribute to be initialized
        Constant.messages = mock(I18N.class);
    }

    protected HttpMessage getMockHttpMessage() throws URIException {
        HistoryReference mockHistoryRef = mock(HistoryReference.class);

        HttpRequestHeader mockReqHeader = mock(HttpRequestHeader.class);
        when(mockReqHeader.getURI()).thenReturn(new URI("http", "example.com", "/", ""));

        HttpMessage mockMessage = mock(HttpMessage.class);
        when(mockMessage.getHistoryRef()).thenReturn(mockHistoryRef);
        when(mockMessage.getRequestHeader()).thenReturn(mockReqHeader);

        return mockMessage;
    }
}
