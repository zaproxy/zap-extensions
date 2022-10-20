/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.selenium;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_MOCKS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.db.RecordHistory;
import org.parosproxy.paros.db.TableAlert;
import org.parosproxy.paros.db.TableHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.TestUtils;

class SeleniumAPIUnitTest extends TestUtils {
    private SeleniumAPI seleniumAPI;
    private TableHistory tableHistory;

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();
        tableHistory =
                mock(TableHistory.class, withSettings().defaultAnswer(RETURNS_MOCKS).lenient());
        HistoryReference.setTableHistory(tableHistory);
        HistoryReference.setTableAlert(
                mock(TableAlert.class, withSettings().defaultAnswer(RETURNS_MOCKS).lenient()));
    }

    @Test
    void shouldNotThrowExceptionsForValidHttpMessage() throws Exception {
        // Given
        seleniumAPI = new SeleniumAPI();
        HttpMessage callBackMessage = new HttpMessage();
        callBackMessage
                .getRequestHeader()
                .setURI(new URI("https://www.localhost.com/?hist=1", true));

        HttpMessage httpMessage = new HttpMessage();
        httpMessage.getRequestHeader().setURI(new URI("https://www.example.com", true));
        httpMessage.getResponseHeader().setStatusCode(200);
        httpMessage.setResponseBody("test");

        RecordHistory recordHistory = mock(RecordHistory.class);
        when(tableHistory.write(anyLong(), anyInt(), eq(httpMessage))).thenReturn(recordHistory);
        when(tableHistory.read(anyInt())).thenReturn(recordHistory);
        when(recordHistory.getHttpMessage()).thenReturn(httpMessage);
        // When
        String body = seleniumAPI.handleCallBack(callBackMessage);
        // Then
        /** Right now it throws URL Not Found in the Scan Tree (url_not_found) */
        assertEquals(body, callBackMessage.getResponseBody().toString());
        assertEquals(
                callBackMessage.getResponseBody().toString(),
                httpMessage.getResponseBody().toString());
    }
}
