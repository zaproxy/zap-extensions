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
package org.zaproxy.zap.extension.alertFilters.llm;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.llm.ExtensionLlm;
import org.zaproxy.addon.llm.services.LlmCommunicationService;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link LlmActionReviewAlert}. */
class LlmActionReviewAlertUnitTest extends TestUtils {

    static ExtensionLlm extLlm;
    static LlmActionReviewAlert action;

    @BeforeAll
    static void beforeEach() {
        Constant.messages = new I18N(Locale.ENGLISH);
        Model model = mock(Model.class);
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        extLlm = mock(ExtensionLlm.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionLlm.class)).willReturn(extLlm);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        action =
                new LlmActionReviewAlert(
                        extLlm,
                        mock(ExtensionAlert.class, withSettings().strictness(Strictness.LENIENT)));
    }

    @Test
    void shouldNotBeConsideredReviewdIfNoTags() {
        // Given
        Alert alert = new Alert(-1);
        // When
        boolean result = LlmActionReviewAlert.isPreviouslyReviewed(alert);
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @Test
    void shouldNotBeConsideredReviewdIfNotMarkedAsSuch() {
        // Given
        Alert alert = new Alert(-1);
        alert.setTags(Map.of("test", "test"));
        // When
        boolean result = LlmActionReviewAlert.isPreviouslyReviewed(alert);
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @Test
    void shouldIncludeAlertTitleAndDescriptionInPrompt() throws Exception {
        // Given
        LlmCommunicationService comms = mock(LlmCommunicationService.class);
        given(extLlm.getCommunicationService(anyString(), anyString())).willReturn(comms);
        ChatResponse resp = mock(ChatResponse.class);
        given(comms.chat(any(ChatRequest.class))).willReturn(resp);
        AiMessage aiMsg = mock(AiMessage.class);
        given(resp.aiMessage()).willReturn(aiMsg);
        given(aiMsg.text()).willReturn("{}");
        ArgumentCaptor<ChatRequest> argument = ArgumentCaptor.forClass(ChatRequest.class);

        Alert alert = new Alert(-1);
        alert.setName("Test Name");
        alert.setDescription("Test Description");

        // When
        action.reviewAlert(alert);

        // Then
        verify(comms).chat(argument.capture());
        contains(argument.getValue().messages().get(0).toString(), "Test Name");
        contains(argument.getValue().messages().get(0).toString(), "Test Description");
    }

    @Test
    void shouldIncludeAlertOtherInfoInPrompt() throws Exception {
        // Given
        LlmCommunicationService comms = mock(LlmCommunicationService.class);
        given(extLlm.getCommunicationService(anyString(), anyString())).willReturn(comms);
        ChatResponse resp = mock(ChatResponse.class);
        given(comms.chat(any(ChatRequest.class))).willReturn(resp);
        AiMessage aiMsg = mock(AiMessage.class);
        given(resp.aiMessage()).willReturn(aiMsg);
        given(aiMsg.text()).willReturn("{}");
        ArgumentCaptor<ChatRequest> argument = ArgumentCaptor.forClass(ChatRequest.class);

        Alert alert = new Alert(-1);
        alert.setOtherInfo("Test Other Info");

        // When
        action.reviewAlert(alert);

        // Then
        verify(comms).chat(argument.capture());
        contains(argument.getValue().messages().get(0).toString(), "Test Other Info");
    }
}
