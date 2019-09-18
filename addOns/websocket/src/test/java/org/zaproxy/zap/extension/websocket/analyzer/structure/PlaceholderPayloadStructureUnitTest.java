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
package org.zaproxy.zap.extension.websocket.analyzer.structure;

import java.util.List;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.WebSocketAddonTestUtils;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.analyzer.analyzer.PayloadAnalyzer;
import org.zaproxy.zap.extension.websocket.analyzer.analyzer.PayloadJSONAnalyzer;
import org.zaproxy.zap.extension.websocket.analyzer.structural.SimpleNameValuePair;
import org.zaproxy.zap.extension.websocket.analyzer.structural.WebSocketNameValuePair;
import org.zaproxy.zap.extension.websocket.utility.InvalidUtf8Exception;

public class PlaceholderPayloadStructureUnitTest extends WebSocketAddonTestUtils {

    @Before
    public void setUp() throws Exception {
        setUpMessages();
        super.setUpLog();
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionWebSocket());
    }

    @Test
    public void shouldAddNameValuesPairsWhenAddAndBuild() throws InvalidUtf8Exception {
        // Given
        WebSocketMessageDTO message = getTextOutgoingMessage("{\"name\":\"value\"}");
        PlaceholderPayloadStructure.Builder payloadStructureBuilder =
                new PlaceholderPayloadStructure.Builder(message);
        SimpleNameValuePair.Builder nameValueBuilder = new SimpleNameValuePair.Builder();

        nameValueBuilder.setName("{@name}").setValue("\"value\"").setPosition(8);

        // When
        payloadStructureBuilder.add(nameValueBuilder.build());

        // Then
        PlaceholderPayloadStructure placeholderPayloadStructure = payloadStructureBuilder.build();
        Assert.assertEquals("{@name}", placeholderPayloadStructure.getList().get(0).getName());
        Assert.assertEquals("\"value\"", placeholderPayloadStructure.getList().get(0).getValue());
        Assert.assertEquals(
                "{\"name\":{@name}}", placeholderPayloadStructure.getPlaceholdedString());
    }

    @Test
    public void shouldNotAddExtraCharactersWhenBuild() throws InvalidUtf8Exception {
        // Given
        WebSocketMessageDTO message = getTextOutgoingMessage("value");
        PlaceholderPayloadStructure.Builder payloadStructureBuilder =
                new PlaceholderPayloadStructure.Builder(message);

        SimpleNameValuePair nameValuePair =
                new SimpleNameValuePair.Builder()
                        .setNameWithMeta("var")
                        .setValue("value")
                        .setPosition(0)
                        .build();

        // When
        PlaceholderPayloadStructure payloadStructure =
                payloadStructureBuilder.add(nameValuePair).build();

        // Then
        Assert.assertEquals("{@var}", payloadStructure.getList().get(0).getName());
        Assert.assertEquals("value", payloadStructure.getList().get(0).getValue());
        Assert.assertEquals("{@var}", payloadStructure.getPlaceholdedString());
    }

    @Test
    public void shouldHaveTheRightPositionWhenBuild() throws InvalidUtf8Exception {
        // Given
        WebSocketMessageDTO message = getTextOutgoingMessage("0123456_This-is-value_222426_value");

        SimpleNameValuePair nameValuePair1 =
                new SimpleNameValuePair.Builder()
                        .setName("name1")
                        .setValue("_This-is-value_")
                        .setPosition(7)
                        .build();

        SimpleNameValuePair nameValuePair2 =
                new SimpleNameValuePair.Builder()
                        .setName("name2")
                        .setValue("_value")
                        .setPosition(28)
                        .build();

        // When
        PayloadStructure payloadStructure =
                new PlaceholderPayloadStructure.Builder(message)
                        .add(nameValuePair1)
                        .add(nameValuePair2)
                        .build();

        // Then
        System.out.println(payloadStructure);
        Assert.assertEquals(7, payloadStructure.getList().get(0).getPosition());
        Assert.assertEquals(18, payloadStructure.getList().get(1).getPosition());
    }

    @Test
    public void shouldHaveTheSamePayloadWhenExecute() throws InvalidUtf8Exception {

        // Given
        WebSocketMessageDTO message = getTextOutgoingMessage("0123456_This-is-value_222426_value");

        SimpleNameValuePair nameValuePair1 =
                new SimpleNameValuePair.Builder()
                        .setName("name1")
                        .setValue("_This-is-value_")
                        .setPosition(7)
                        .build();

        SimpleNameValuePair nameValuePair2 =
                new SimpleNameValuePair.Builder()
                        .setNameWithMeta("name2")
                        .setValue("_value")
                        .setPosition(28)
                        .build();

        PayloadStructure payloadStructure =
                new PlaceholderPayloadStructure.Builder(message)
                        .add(nameValuePair1)
                        .add(nameValuePair2)
                        .build();

        // When
        WebSocketMessageDTO exportedMessage = payloadStructure.execute();

        // Then
        Assert.assertEquals(message.getReadablePayload(), exportedMessage.getReadablePayload());
    }

    @Test
    public void shouldCreateAppropriatePayloadWhenChangeValuesAndExecute()
            throws InvalidUtf8Exception {
        // Given
        WebSocketMessageDTO message =
                getTextOutgoingMessage(
                        "{\n"
                                + "            \"notify\": {\n"
                                + "                \"event\": \"updateModels\",\n"
                                + "                \"typeName\": \"Member\",\n"
                                + "                \"deltas\": [{\n"
                                + "                    \"id\": \"5be9ad94e2320147bc\",\n"
                                + "                    \"oneTimeMessagesDismissed\": [\"simplified-view-full-view\",\n"
                                + "                        \"create-first-board\",\n"
                                + "                        \"simplified-view-org-settings\",\n"
                                + "                        \"simplified-view-card-activity\",\n"
                                + "                        \"simplified-view-card-move\",\n"
                                + "                        \"simplified-view-labels-and-edit\",\n"
                                + "                        \"homeHighlightsOrientationCard\",\n"
                                + "                        \"close-menu-of-first-board\"\n"
                                + "                    ]\n"
                                + "                }],\n"
                                + "                \"tags\": [\"self\", \"messages\"],\n"
                                + "                \"idMember\": \"5be9ad94e2320147bc\"\n"
                                + "            },\n"
                                + "            \"idModelChannel\": \"5be9ad94e2320147bc\",\n"
                                + "            \"ixLastUpdateChannel\": 21\n"
                                + "        }");

        String expectedPayload =
                "{\n"
                        + "            \"notify\": {\n"
                        + "                \"event\": \"updatedValues1\",\n"
                        + "                \"typeName\": \"updatedValues2\",\n"
                        + "                \"deltas\": [{\n"
                        + "                    \"id\": \"updatedValues3\",\n"
                        + "                    \"oneTimeMessagesDismissed\": [\"simplified-view-full-view\",\n"
                        + "                        \"create-first-board\",\n"
                        + "                        \"simplified-view-org-settings\",\n"
                        + "                        \"updatedValues4\",\n"
                        + "                        \"simplified-view-card-move\",\n"
                        + "                        \"simplified-view-labels-and-edit\",\n"
                        + "                        \"homeHighlightsOrientationCard\",\n"
                        + "                        \"close-menu-of-first-board\"\n"
                        + "                    ]\n"
                        + "                }],\n"
                        + "                \"tags\": [\"self\", \"messages\"],\n"
                        + "                \"idMember\": \"updatedValues5\"\n"
                        + "            },\n"
                        + "            \"idModelChannel\": \"5be9ad94e2320147bc\",\n"
                        + "            \"ixLastUpdateChannel\": 12552\n"
                        + "        }";

        PayloadAnalyzer jsonAnalyzer = new PayloadJSONAnalyzer();

        PayloadStructure payloadStructure = jsonAnalyzer.parse(message);

        // When
        List<WebSocketNameValuePair> parameters = payloadStructure.getList();

        parameters.get(0).setValue("\"updatedValues1\"");
        parameters.get(1).setValue("\"updatedValues2\"");
        parameters.get(2).setValue("\"updatedValues3\"");
        parameters.get(6).setValue("\"updatedValues4\"");
        parameters.get(13).setValue("\"updatedValues5\"");
        parameters.get(15).setValue("12552");

        // Then
        Assert.assertEquals(expectedPayload, payloadStructure.execute().getReadablePayload());
    }
}
