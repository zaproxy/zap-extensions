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
package org.zaproxy.zap.extension.websocket.analyzer;

import static net.sf.ezmorph.test.ArrayAssertions.assertEquals;
import static org.hamcrest.Matchers.contains;
import static org.junit.Assert.assertThat;

import java.util.ArrayList;
import java.util.List;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.WebSocketAddonTestUtils;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.analyzer.analyzer.PayloadAnalyzer;
import org.zaproxy.zap.extension.websocket.analyzer.analyzer.PayloadJSONAnalyzer;
import org.zaproxy.zap.extension.websocket.analyzer.structural.WebSocketNameValuePair;
import org.zaproxy.zap.extension.websocket.analyzer.structure.PayloadStructure;
import org.zaproxy.zap.extension.websocket.utility.InvalidUtf8Exception;

public class PayloadJSONAnalyzerUnitTest extends WebSocketAddonTestUtils {

    private PayloadAnalyzer jsonAnalyzer;

    @Before
    public void setUp() throws Exception {
        setUpMessages();
        super.setUpLog();
        jsonAnalyzer = new PayloadJSONAnalyzer();
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionWebSocket());
    }

    @Test
    public void shouldBeRecognizable() throws InvalidUtf8Exception {
        // Given
        List<WebSocketMessageDTO> messages =
                messages(
                        getTextOutgoingMessage("{}"),
                        getTextOutgoingMessage("[1,53578907,\"psi\",16,234,80]"),
                        getTextOutgoingMessage("123"),
                        getTextOutgoingMessage("\"string\""),
                        getTextOutgoingMessage("null"),
                        getTextOutgoingMessage("true"),
                        getTextOutgoingMessage("[\"array item 1\", 123]\n"),
                        getTextOutgoingMessage("{ \"property\": \"value\" }"));

        // When
        for (WebSocketMessageDTO message : messages) {
            System.out.println(message.getReadablePayload());
            // Then
            Assert.assertNotNull(jsonAnalyzer.parse(message));
        }
    }

    @Test
    public void shouldBeAddedAsDifferentWebSocketNameValuePair() throws InvalidUtf8Exception {
        // Given
        List<WebSocketMessageDTO> messages =
                messages(
                        getTextOutgoingMessage("{}"), // size = 0
                        getTextOutgoingMessage("[1,53578907,\"psi\",16,234,80]"), // size = 6
                        getTextOutgoingMessage("123"), // size = 1
                        getTextOutgoingMessage("[123, 321]"), // size = 2
                        getTextOutgoingMessage("\"string\""), // size = 1
                        getTextOutgoingMessage("null"), // size = 1
                        getTextOutgoingMessage("true"), // size = 1
                        getTextOutgoingMessage("[\"array item 1\", 123]\n"), // size = 2
                        getTextOutgoingMessage("{ \"property\": \"value\" }") // size = 1
                        );
        int[] evalSize = {0, 6, 1, 2, 1, 1, 1, 2, 1};

        // When
        List<PayloadStructure> payloadStructures = new ArrayList<>();
        for (WebSocketMessageDTO message : messages) {
            payloadStructures.add(jsonAnalyzer.parse(message));
        }

        // Then
        for (int i = 0; i < evalSize.length; i++) {
            assertEquals(evalSize[i], payloadStructures.get(i).getList().size());
        }
    }

    @Test
    public void shouldAddTheAppropriateNames() {
        // Given
        WebSocketMessageDTO message =
                getTextOutgoingMessage(
                        "{\n"
                                + "    \"notify\": {\n"
                                + "        \"event\": \"updateModels\",\n"
                                + "        \"typeName\": \"Member\",\n"
                                + "        \"deltas\": [{\n"
                                + "            \"id\": \"5be9ad94e2320147bc084d39\",\n"
                                + "            \"oneTimeMessagesDismissed\": [\"simplified-view-full-view\", \"create-first-board\", \"simplified-view-org-settings\", \"simplified-view-card-activity\", \"simplified-view-card-move\", \"simplified-view-labels-and-edit\", \"homeHighlightsOrientationCard\", \"close-menu-of-first-board\"]\n"
                                + "        }],\n"
                                + "        \"tags\": [\"self\", \"messages\"],\n"
                                + "        \"idMember\": \"5be9ad94e2320147bc084d39\"\n"
                                + "    },\n"
                                + "    \"idModelChannel\": \"5be9ad94e2320147bc084d39\",\n"
                                + "    \"ixLastUpdateChannel\": 21\n"
                                + "}\n");

        // When
        ArrayList<String> names = new ArrayList<>();
        for (WebSocketNameValuePair pair : jsonAnalyzer.parse(message).getList()) {
            names.add(pair.getName());
        }

        // Then
        assertThat(
                names,
                contains(
                        "event",
                        "typeName",
                        "id",
                        "oneTimeMessagesDismissed[0]",
                        "oneTimeMessagesDismissed[1]",
                        "oneTimeMessagesDismissed[2]",
                        "oneTimeMessagesDismissed[3]",
                        "oneTimeMessagesDismissed[4]",
                        "oneTimeMessagesDismissed[5]",
                        "oneTimeMessagesDismissed[6]",
                        "oneTimeMessagesDismissed[7]",
                        "tags[0]",
                        "tags[1]",
                        "idMember",
                        "idModelChannel",
                        "ixLastUpdateChannel"));
    }

    @Test
    public void shouldAddTheAppropriateValues() {

        // Given
        WebSocketMessageDTO messages =
                getTextOutgoingMessage(
                        "{\n"
                                + "   \"id\":\"TM49270343a7dd46898307a29d7f25c938\",\n"
                                + "   \"method\":\"reply\",\n"
                                + "   \"payload_type\":\"application/json\",\n"
                                + "   \"status\":{\n"
                                + "      \"code\":200,\n"
                                + "      \"status\":\"OK\"\n"
                                + "   },\n"
                                + "   \"payload_size\":0\n"
                                + "}");
        // When
        PayloadStructure payloadStructure = jsonAnalyzer.parse(messages);
        ArrayList<String> actualValues = new ArrayList<>();
        for (WebSocketNameValuePair pair : payloadStructure.getList()) {
            actualValues.add(pair.getValue());
        }

        // Then
        assertThat(
                actualValues,
                contains(
                        "\"TM49270343a7dd46898307a29d7f25c938\"",
                        "\"reply\"",
                        "\"application/json\"",
                        "200",
                        "\"OK\"",
                        "0"));
    }
}
