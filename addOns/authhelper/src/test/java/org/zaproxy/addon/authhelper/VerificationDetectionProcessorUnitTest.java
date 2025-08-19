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
package org.zaproxy.addon.authhelper;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.sameInstance;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.testutils.NanoServerHandler;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit test for {@link VerificationDetectionProcessor}. */
class VerificationDetectionProcessorUnitTest extends TestUtils {

    private static final String SESSION_TOKEN = "token";

    private static final VerificationRequestDetails NO_DETAILS = new VerificationRequestDetails();

    private Supplier<Response> missingSessionResponse;
    private HttpMessage verificationMessage;

    private AuthenticationMethod authenticationMethod;
    private Context context;

    private VerificationDetectionScanRule rule;
    private PluginPassiveScanner.AlertBuilder alertBuilder;

    private VerificationDetectionProcessor processor;

    @BeforeAll
    static void setUpAll() {
        mockMessages(new ExtensionAuthhelper());
    }

    @BeforeEach
    void setUp() throws Exception {
        context = mock();
        given(context.getId()).willReturn(1);

        rule = mock();

        AuthUtils.setVerificationDetailsForContext(context.getId(), NO_DETAILS);

        setUpZap();
        startServer();

        missingSessionResponse = () -> newFixedLengthResponse("");
        String path = "/";
        verificationMessage = getHttpMessage(path);
        String sessionHeader = "my-auth-header";
        verificationMessage.getRequestHeader().setHeader(sessionHeader, SESSION_TOKEN);
        nano.addHandler(
                new NanoServerHandler(path) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        if (SESSION_TOKEN.equals(session.getHeaders().get(sessionHeader))) {
                            return newFixedLengthResponse("<html>Welcome</html>");
                        }
                        return missingSessionResponse.get();
                    }
                });
    }

    @AfterEach
    void cleanUp() {
        AuthUtils.clean();
    }

    @Test
    void shouldNotUseDetailsWithoutEvidence() {
        // Given
        VerificationRequestDetails details =
                new VerificationRequestDetails(verificationMessage, SESSION_TOKEN, context);
        processor = new VerificationDetectionProcessor(context, details, rule);

        // When
        processor.run();

        // Then
        verifyNoInteractions(rule);
        assertThat(
                AuthUtils.getVerificationDetailsForContext(context.getId()),
                is(sameInstance(NO_DETAILS)));
        verify(context, never()).getAuthenticationMethod();
    }

    @Test
    void shouldUseDetailsWithStatusCodeEvidence() {
        // Given
        authenticationMethod = mock();
        given(context.getAuthenticationMethod()).willReturn(authenticationMethod);
        alertBuilder = mock();
        given(rule.getAlert(any())).willReturn(alertBuilder);

        missingSessionResponse =
                () ->
                        newFixedLengthResponse(
                                Response.Status.REDIRECT_SEE_OTHER, NanoHTTPD.MIME_HTML, "");
        VerificationRequestDetails details =
                new VerificationRequestDetails(verificationMessage, SESSION_TOKEN, context);
        processor = new VerificationDetectionProcessor(context, details, rule);

        // When
        processor.run();

        // Then
        assertThat(
                AuthUtils.getVerificationDetailsForContext(context.getId()),
                is(sameInstance(details)));
        verify(authenticationMethod).setLoggedInIndicatorPattern("\\Q 200 OK\\E");
        verify(authenticationMethod).setLoggedOutIndicatorPattern("\\Q 303 See Other\\E");
    }

    @Test
    void shouldRaiseAlertWithGoodDetails() {
        // Given
        authenticationMethod = mock();
        given(context.getAuthenticationMethod()).willReturn(authenticationMethod);
        alertBuilder = mock();
        given(rule.getAlert(any())).willReturn(alertBuilder);

        missingSessionResponse =
                () ->
                        newFixedLengthResponse(
                                Response.Status.REDIRECT_SEE_OTHER, NanoHTTPD.MIME_HTML, "");
        VerificationRequestDetails details =
                new VerificationRequestDetails(verificationMessage, SESSION_TOKEN, context);
        processor = new VerificationDetectionProcessor(context, details, rule);

        // When
        processor.run();

        // Then
        verify(rule).getAlert(details);
        verify(alertBuilder).raise();
    }
}
