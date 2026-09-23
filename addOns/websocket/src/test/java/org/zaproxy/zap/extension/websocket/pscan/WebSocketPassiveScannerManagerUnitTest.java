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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Iterator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.websocket.alerts.AlertManager;
import org.zaproxy.zap.testutils.WebSocketTestUtils;

class WebSocketPassiveScannerManagerUnitTest extends WebSocketTestUtils {

    private WebSocketPassiveScannerManager wsPscanManager;

    @BeforeEach
    void setUp() {
        wsPscanManager = new WebSocketPassiveScannerManager(mock(AlertManager.class));
    }

    @Test
    void shouldHaveNoScannerByDefault() {
        assertFalse(wsPscanManager.getIterator().hasNext());
    }

    @Test
    void shouldAddWebSocketPassiveScanner() {
        // Given
        WebSocketPassiveScanner wsScanner = mock(WebSocketPassiveScanner.class);
        // When
        boolean result = wsPscanManager.add(wsScanner);
        // Then
        assertTrue(result);
        assertTrue(wsPscanManager.getIterator().hasNext());
    }

    @Test
    void shouldAllowPassiveScannersWithSameNameButDifferentId() {
        // Given
        // Scanner 1
        WebSocketPassiveScanner wsScanner1 = mock(WebSocketPassiveScanner.class);
        lenient().when(wsScanner1.getName()).thenReturn("WebSocketPassiveScanner-1");
        when(wsScanner1.getId()).thenReturn(1);
        // Scanner 2 - same name, different id, e.g. a script copied without changing its name
        WebSocketPassiveScanner wsScanner2 = mock(WebSocketPassiveScanner.class);
        lenient().when(wsScanner2.getName()).thenReturn("WebSocketPassiveScanner-1");
        when(wsScanner2.getId()).thenReturn(2);

        // When
        boolean resultPlugin1 = wsPscanManager.add(wsScanner1);
        boolean resultPlugin2 = wsPscanManager.add(wsScanner2);

        // Then
        assertTrue(resultPlugin1);
        assertTrue(resultPlugin2);
        assertTrue(wsPscanManager.isContained(wsScanner1));
        assertTrue(wsPscanManager.isContained(wsScanner2));
    }

    @Test
    void shouldIgnorePassiveScannerWithSameId() {
        // Given
        // Scanner 1
        WebSocketPassiveScanner wsScanner1 = mock(WebSocketPassiveScanner.class);
        lenient().when(wsScanner1.getName()).thenReturn("WebSocketPassiveScanner-1");
        when(wsScanner1.getId()).thenReturn(1);
        // Scanner 2 - different name, same id
        WebSocketPassiveScanner wsScanner2 = mock(WebSocketPassiveScanner.class);
        when(wsScanner2.getName()).thenReturn("WebSocketPassiveScanner-2");
        when(wsScanner2.getId()).thenReturn(1);

        // When
        boolean resultPlugin1 = wsPscanManager.add(wsScanner1);
        boolean resultPlugin2 = wsPscanManager.add(wsScanner2);

        // Then
        assertTrue(resultPlugin1);
        assertTrue(wsPscanManager.isContained(wsScanner1));
        assertFalse(resultPlugin2);
    }

    @Test
    void shouldRemovePassiveScanner() {
        // Given
        WebSocketPassiveScanner scanner1 = mock(WebSocketPassiveScanner.class);
        when(scanner1.getId()).thenReturn(1);
        boolean resultPlugin1 = wsPscanManager.add(scanner1);

        WebSocketPassiveScanner scanner2 = mock(WebSocketPassiveScanner.class);
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
    void shouldAllowToChangeWhileIterating() {
        // Given
        WebSocketPassiveScanner scanner1 = mock(WebSocketPassiveScanner.class);
        when(scanner1.getId()).thenReturn(1);
        wsPscanManager.add(scanner1);

        WebSocketPassiveScanner scanner2 = mock(WebSocketPassiveScanner.class);
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
    void shouldAddScannerDisabledByDefault() {
        // Given
        WebSocketPassiveScanner scanner = mock(WebSocketPassiveScanner.class);
        lenient().when(scanner.getName()).thenReturn("WsScanner-1");
        lenient().when(scanner.getId()).thenReturn(1);

        // When
        wsPscanManager.add(scanner);

        // Then
        assertFalse(wsPscanManager.isEnabled(scanner));
    }

    @Test
    void shouldEnableScannerAddedAfterSetAllEnableTrue() {
        // Given — mirrors ExtensionWebSocket.hook(), which enables everything added so far, then
        // scripts are added later (e.g. bundled default scripts loaded in postInit(), or a script
        // added by the user at runtime)
        wsPscanManager.setAllEnable(true);
        WebSocketPassiveScanner scanner = mock(WebSocketPassiveScanner.class);
        lenient().when(scanner.getName()).thenReturn("WsScanner-1");
        lenient().when(scanner.getId()).thenReturn(1);

        // When
        wsPscanManager.add(scanner);

        // Then
        assertTrue(wsPscanManager.isEnabled(scanner));
    }

    @Test
    void shouldKeepAddingScannersDisabledAfterSetAllEnableFalse() {
        // Given
        wsPscanManager.setAllEnable(true);
        wsPscanManager.setAllEnable(false);
        WebSocketPassiveScanner scanner = mock(WebSocketPassiveScanner.class);
        lenient().when(scanner.getName()).thenReturn("WsScanner-1");
        lenient().when(scanner.getId()).thenReturn(1);

        // When
        wsPscanManager.add(scanner);

        // Then
        assertFalse(wsPscanManager.isEnabled(scanner));
    }

    @Test
    void shouldDisableScanner() {
        // Given
        WebSocketPassiveScanner scanner1 = mock(WebSocketPassiveScanner.class);

        // When
        wsPscanManager.setAllEnable(true);
        wsPscanManager.setEnable(scanner1, false);

        // Then
        Iterator<WebSocketPassiveScannerDecorator> iterator = wsPscanManager.getIterator();
        assertFalse(iterator.hasNext());
    }

    @Test
    void shouldHaveNoScannersByDefault() {
        assertThat(wsPscanManager.getScanners(), is(empty()));
    }

    @Test
    void shouldReturnAddedScannerInGetScanners() {
        // Given
        WebSocketPassiveScanner scanner = mock(WebSocketPassiveScanner.class);
        lenient().when(scanner.getName()).thenReturn("WsScanner-1");
        lenient().when(scanner.getId()).thenReturn(1);
        wsPscanManager.add(scanner);

        // When / Then
        assertThat(wsPscanManager.getScanners(), contains(scanner));
    }

    @Test
    void shouldReportEnabledState() {
        // Given
        WebSocketPassiveScanner scanner = mock(WebSocketPassiveScanner.class);
        lenient().when(scanner.getName()).thenReturn("WsScanner-1");
        lenient().when(scanner.getId()).thenReturn(1);
        wsPscanManager.add(scanner);

        // When
        wsPscanManager.setEnable(scanner, true);

        // Then
        assertTrue(wsPscanManager.isEnabled(scanner));
    }

    @Test
    void shouldReportDisabledForUnknownScanner() {
        // Given
        WebSocketPassiveScanner scanner = mock(WebSocketPassiveScanner.class);

        // When / Then
        assertFalse(wsPscanManager.isEnabled(scanner));
    }

    @Test
    void shouldNotifyGspmRegistrarWhenScannerAdded() {
        // Given
        GspmWebSocketPassiveScanRegistrar gspmRegistrar =
                mock(GspmWebSocketPassiveScanRegistrar.class);
        wsPscanManager.setGspmRegistrar(gspmRegistrar);
        WebSocketPassiveScanner scanner = mock(WebSocketPassiveScanner.class);
        lenient().when(scanner.getName()).thenReturn("WsScanner-1");
        lenient().when(scanner.getId()).thenReturn(1);

        // When
        wsPscanManager.add(scanner);

        // Then
        verify(gspmRegistrar).ruleAdded(scanner);
    }

    @Test
    void shouldNotNotifyGspmRegistrarWhenScannerNotActuallyAdded() {
        // Given
        GspmWebSocketPassiveScanRegistrar gspmRegistrar =
                mock(GspmWebSocketPassiveScanRegistrar.class);
        wsPscanManager.setGspmRegistrar(gspmRegistrar);
        WebSocketPassiveScanner scanner = mock(WebSocketPassiveScanner.class);
        lenient().when(scanner.getName()).thenReturn("WsScanner-1");
        lenient().when(scanner.getId()).thenReturn(1);
        wsPscanManager.add(scanner);
        verify(gspmRegistrar).ruleAdded(scanner);

        // When — adding the same (already-contained) scanner again fails
        wsPscanManager.add(scanner);

        // Then — still only the one notification from the first, successful add
        verify(gspmRegistrar).ruleAdded(scanner);
    }

    @Test
    void shouldNotifyGspmRegistrarWhenScannerRemoved() {
        // Given
        GspmWebSocketPassiveScanRegistrar gspmRegistrar =
                mock(GspmWebSocketPassiveScanRegistrar.class);
        wsPscanManager.setGspmRegistrar(gspmRegistrar);
        WebSocketPassiveScanner scanner = mock(WebSocketPassiveScanner.class);
        lenient().when(scanner.getName()).thenReturn("WsScanner-1");
        lenient().when(scanner.getId()).thenReturn(1);
        wsPscanManager.add(scanner);

        // When
        wsPscanManager.removeScanner(scanner);

        // Then
        verify(gspmRegistrar).ruleRemoved(1);
    }

    @Test
    void shouldNotNotifyGspmRegistrarWhenScannerNotActuallyRemoved() {
        // Given
        GspmWebSocketPassiveScanRegistrar gspmRegistrar =
                mock(GspmWebSocketPassiveScanRegistrar.class);
        wsPscanManager.setGspmRegistrar(gspmRegistrar);
        WebSocketPassiveScanner scanner = mock(WebSocketPassiveScanner.class);
        lenient().when(scanner.getName()).thenReturn("WsScanner-1");
        lenient().when(scanner.getId()).thenReturn(1);

        // When — scanner was never added
        wsPscanManager.removeScanner(scanner);

        // Then
        verify(gspmRegistrar, never()).ruleRemoved(1);
    }

    @Test
    void shouldNotNotifyWhenNoGspmRegistrarSet() {
        // Given — setGspmRegistrar was never called
        WebSocketPassiveScanner scanner = mock(WebSocketPassiveScanner.class);
        lenient().when(scanner.getName()).thenReturn("WsScanner-1");
        lenient().when(scanner.getId()).thenReturn(1);

        // When / Then
        assertTrue(wsPscanManager.add(scanner));
        assertTrue(wsPscanManager.removeScanner(scanner));
    }
}
