/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.alerts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.testutils.WebSocketTestUtils;

class WebSocketAlertRaiserUnitTest extends WebSocketTestUtils {

    @BeforeEach
    void setUp() throws Exception {
        super.setUpZap();
    }

    @Test
    void shouldBuildAlert() {
        // Given
        WebSocketAlertThread webSocketAlertThread = mock(WebSocketAlertThread.class);
        WebSocketMessageDTO message = mock(WebSocketMessageDTO.class);
        given(message.getChannel()).willReturn(mock(WebSocketChannelDTO.class));
        given(message.getChannel().getId()).willReturn(1);
        WebSocketAlertRaiser alertRaiser =
                new WebSocketAlertRaiser(webSocketAlertThread, 0, message);

        // When
        alertRaiser.setName("Name");
        alertRaiser.setDescription("Description");
        alertRaiser.setSource(Alert.Source.MANUAL);
        WebSocketAlertWrapper alertWrapper = alertRaiser.raise();

        // Then
        assertEquals(0, alertWrapper.getAlert().getPluginId());
        assertEquals(Alert.Source.MANUAL, alertWrapper.getSource());
        assertEquals("Name", alertWrapper.getName());
        assertEquals("Description", alertWrapper.getDescription());
    }

    @Test
    void shouldNotBuildAlertWhenMissingNameAndSource() {
        // Given
        WebSocketAlertThread webSocketAlertThread = mock(WebSocketAlertThread.class);
        WebSocketMessageDTO message = mock(WebSocketMessageDTO.class);
        given(message.getChannel()).willReturn(mock(WebSocketChannelDTO.class));
        given(message.getChannel().getId()).willReturn(1);
        WebSocketAlertRaiser alertRaiser =
                new WebSocketAlertRaiser(webSocketAlertThread, 0, message);
        // When
        IllegalStateException e =
                assertThrows(IllegalStateException.class, () -> alertRaiser.raise());
        // Then
        assertTrue(e.getMessage().contains("Alert Name"));
        assertTrue(e.getMessage().contains("Alert Source"));
    }
}
