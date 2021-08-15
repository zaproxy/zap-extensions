/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.oast;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.db.TableTag;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.TestUtils;

class OastRequestUnitTests extends TestUtils {

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();
    }

    @Test
    void shouldCreateValidOastRequest() throws Exception {
        // Given
        String source = "192.0.2.0:12345";
        String handler = "expected handler";
        String referer = "expected referer";
        HttpMessage httpMessage = new HttpMessage(new URI("https://example.com", true));
        httpMessage.getRequestHeader().setHeader(HttpHeader.REFERER, referer);

        TableHistory tableHistory = mock(TableHistory.class);
        RecordHistory recordHistory = mock(RecordHistory.class);
        HistoryReference.setTableHistory(tableHistory);
        when(tableHistory.write(anyLong(), anyInt(), eq(httpMessage))).thenReturn(recordHistory);
        when(tableHistory.read(anyInt())).thenReturn(recordHistory);
        when(recordHistory.getHttpMessage()).thenReturn(httpMessage);

        HistoryReference.setTableAlert(mock(TableAlert.class));

        TableTag tableTag = mock(TableTag.class);
        HistoryReference.setTableTag(tableTag);
        when(tableTag.insert(anyLong(), any())).thenReturn(null);

        // When
        OastRequest oastRequest = OastRequest.create(httpMessage, source, handler);

        // Then
        assertThat(oastRequest.getSource(), is(source));
        assertThat(oastRequest.getHandler(), is(handler));
        assertThat(oastRequest.getReferer(), is(referer));
    }
}
