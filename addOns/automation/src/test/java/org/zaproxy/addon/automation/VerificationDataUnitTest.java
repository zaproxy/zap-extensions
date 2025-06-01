/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.authentication.AuthenticationMethod.AuthCheckingStrategy;
import org.zaproxy.zap.authentication.HttpAuthenticationMethodType.HttpAuthenticationMethod;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.I18N;

class VerificationDataUnitTest {

    private static Stream<Arguments> shouldSetCorrectAuthenticationMethod() {
        return Stream.of(
                arguments("both", AuthCheckingStrategy.EACH_REQ_RESP),
                arguments("request", AuthCheckingStrategy.EACH_REQ),
                arguments("response", AuthCheckingStrategy.EACH_RESP),
                arguments("poll", AuthCheckingStrategy.POLL_URL));
    }

    @ParameterizedTest
    @MethodSource
    void shouldSetCorrectAuthenticationMethod(
            String method, AuthCheckingStrategy authCheckingStrategy) {
        // Given
        HttpAuthenticationMethod httpAuthMethod = new HttpAuthenticationMethod();
        httpAuthMethod.setHostname("https://www.example.com");
        httpAuthMethod.setRealm("realm");
        httpAuthMethod.setPort(123);
        Constant.messages = new I18N(Locale.ENGLISH);
        Context context = mock(Context.class);
        AutomationProgress progress = new AutomationProgress();
        LinkedHashMap<String, Object> data = new LinkedHashMap<>();
        given(context.getAuthenticationMethod()).willReturn(httpAuthMethod);
        data.put("method", method);
        VerificationData verificationData = new VerificationData(data, progress);

        // When
        verificationData.initAuthenticationVerification(context, progress);

        // Then
        assertThat(
                context.getAuthenticationMethod().getAuthCheckingStrategy(),
                is(authCheckingStrategy));
    }
}
