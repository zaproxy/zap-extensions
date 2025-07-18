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
package org.zaproxy.addon.llm.services;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasEntry;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.llm.communication.Confidence;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link LlmCommunicationService}. */
class LlmCommunicationServiceUnitTest extends TestUtils {

    private static final Confidence CONFIDENCE =
            new Confidence(Alert.CONFIDENCE_MEDIUM, "explanation");

    @BeforeAll
    static void beforeAll() {
        Constant.messages = mock(I18N.class);
    }

    @Test
    void shouldNotBeConsideredReviewdIfNoTags() {
        // Given
        Alert alert = new Alert(-1);
        // When
        boolean result = LlmCommunicationService.isPreviouslyReviewed(alert);
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @Test
    void shouldNotBeConsideredReviewdIfNotMarkedAsSuch() {
        // Given
        Alert alert = new Alert(-1);
        alert.setTags(Map.of("test", "test"));
        // When
        boolean result = LlmCommunicationService.isPreviouslyReviewed(alert);
        // Then
        assertThat(result, is(equalTo(false)));
    }

    @Test
    void shouldBeConsideredReviewdIfMarkedAsSuch() {
        // Given
        Alert alert = new Alert(-1);
        alert.setTags(Map.of(LlmCommunicationService.AI_REVIEWED_TAG_KEY, ""));
        // When
        boolean result = LlmCommunicationService.isPreviouslyReviewed(alert);
        // Then
        assertThat(result, is(equalTo(true)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "  ", "\t", "\r", "\n"})
    void shouldUseTwoParamReviewMethodWhenNoOtherInfo(String otherInfo) {
        // Given
        LlmAssistant assistant = mock();
        LlmCommunicationService service = new LlmCommunicationService(assistant);

        Alert alert = createBaseAlert();
        alert.setOtherInfo(otherInfo);

        given(assistant.review(anyString(), anyString())).willReturn(CONFIDENCE);
        // When
        service.reviewAlert(alert);
        // Then
        verify(assistant).review(anyString(), anyString());
        assertThat(alert.getTags(), hasEntry(LlmCommunicationService.AI_REVIEWED_TAG_KEY, ""));
    }

    @Test
    void shouldUseThreeParamReviewMethodWhenHasOtherInfo() {
        // Given
        LlmAssistant assistant = mock();
        LlmCommunicationService service = new LlmCommunicationService(assistant);

        Alert alert = createBaseAlert();
        alert.setOtherInfo("other info");

        given(assistant.review(anyString(), anyString(), anyString())).willReturn(CONFIDENCE);
        // When
        service.reviewAlert(alert);
        // Then
        verify(assistant).review(anyString(), anyString(), anyString());
        assertThat(alert.getTags(), hasEntry(LlmCommunicationService.AI_REVIEWED_TAG_KEY, ""));
    }

    private static Alert createBaseAlert() {
        return Alert.builder()
                .setDescription("desc")
                .setEvidence("evidence")
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .build();
    }
}
