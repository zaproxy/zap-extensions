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
package org.zaproxy.zap.extension.websocket.pscan;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Iterator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.websocket.alerts.AlertManager;
import org.zaproxy.zap.testutils.WebSocketTestUtils;

public class WebSocketPassiveScannerManagerUnitTest extends WebSocketTestUtils {

    private WebSocketPassiveScannerManager wsPscanManager;

    @BeforeEach
    public void setUp() {
        wsPscanManager = new WebSocketPassiveScannerManager(mock(AlertManager.class));
    }

    @Test
    public void shouldHaveNoScannerByDefault() {
        assertFalse(wsPscanManager.getIterator().hasNext());
    }

    @Test
    public void shouldAddWebSocketPassiveScanner() {
        // Given
        WebSocketPassiveScanner wsScanner = mock(WebSocketPassiveScanner.class);
        // When
        boolean result = wsPscanManager.add(wsScanner);
        // Then
        assertTrue(result);
        assertTrue(wsPscanManager.getIterator().hasNext());
    }

    @Test
    public void shouldIgnorePassiveScannerWithSameName() {
        // Given
        // Scanner 1
        WebSocketPassiveScanner wsScanner1 = mock(WebSocketPassiveScanner.class);
        when(wsScanner1.getName()).thenReturn("WebSocketPassiveScanner-1");
        when(wsScanner1.getId()).thenReturn(1);
        // Scanner 2
        WebSocketPassiveScanner wsScanner2 = mock(WebSocketPassiveScanner.class);
        when(wsScanner2.getName()).thenReturn("WebSocketPassiveScanner-1");
        when(wsScanner2.getId()).thenReturn(2);

        // When
        boolean resultPlugin1 = wsPscanManager.add(wsScanner1);
        boolean resultPlugin2 = wsPscanManager.add(wsScanner2);

        // Then
        assertTrue(resultPlugin1);
        assertTrue(wsPscanManager.isContained(wsScanner1));
        assertFalse(resultPlugin2);
    }

    @Test
    public void shouldRemovePassiveScanner() {
        // Given
        WebSocketPassiveScanner scanner1 = mock(WebSocketPassiveScanner.class);
        when(scanner1.getName()).thenReturn("WsScanner-1");
        when(scanner1.getId()).thenReturn(1);
        boolean resultPlugin1 = wsPscanManager.add(scanner1);

        WebSocketPassiveScanner scanner2 = mock(WebSocketPassiveScanner.class);
        when(scanner2.getName()).thenReturn("WsScanner-2");
        when(scanner2.getId()).thenReturn(2);
        wsPscanManager.add(scanner2);

        // When
        boolean result = wsPscanManager.removeScanner(scanner2);

        // Then
        assertTrue(resultPlugin1);
        assertTrue(result);
        assertFalse(wsPscanManager.isContained(scanner2));
    }

    @Test
    public void shouldAllowToChangeWhileIterating() {
        // Given
        WebSocketPassiveScanner scanner1 = mock(WebSocketPassiveScanner.class);
        when(scanner1.getName()).thenReturn("WsScanner-1");
        when(scanner1.getId()).thenReturn(1);
        wsPscanManager.add(scanner1);

        WebSocketPassiveScanner scanner2 = mock(WebSocketPassiveScanner.class);
        when(scanner2.getName()).thenReturn("WsScanner-2");
        when(scanner2.getId()).thenReturn(2);
        wsPscanManager.add(scanner2);

        // When
        Iterator<WebSocketPassiveScannerDecorator> iterator = wsPscanManager.getIterator();
        while (iterator.hasNext()) {
            WebSocketPassiveScanner iScanner = iterator.next();
            wsPscanManager.removeScanner(iScanner);
            wsPscanManager.add(iScanner);
        }

        // Then
        assertTrue(wsPscanManager.isContained(scanner1));
        assertTrue(wsPscanManager.isContained(scanner2));
    }

    @Test
    public void shouldDisableScanner() {
        // Given
        WebSocketPassiveScanner scanner1 = mock(WebSocketPassiveScanner.class);

        // When
        wsPscanManager.setAllEnable(true);
        wsPscanManager.setEnable(scanner1, false);

        // Then
        Iterator<WebSocketPassiveScannerDecorator> iterator = wsPscanManager.getIterator();
        assertFalse(iterator.hasNext());
    }
}
