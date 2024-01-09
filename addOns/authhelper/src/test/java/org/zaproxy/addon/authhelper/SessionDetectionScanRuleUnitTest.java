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
package org.zaproxy.addon.authhelper;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.authhelper.HeaderBasedSessionManagementMethodType.HeaderBasedSessionManagementMethod;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethod.AuthCheckingStrategy;
import org.zaproxy.zap.extension.pscan.PassiveScanData;
import org.zaproxy.zap.extension.pscan.PassiveScanTaskHelper;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.utils.I18N;

/** Unit test for {@link SessionDetectionScanRule}. */
class SessionDetectionScanRuleUnitTest extends PassiveScannerTest<SessionDetectionScanRule> {

    @Override
    protected SessionDetectionScanRule createScanner() {
        return new SessionDetectionScanRule();
    }

    private ExtensionLoader extensionLoader;

    private Context context;
    private Model model;

    @Test
    void shouldSetHeaderBasedSessionManagment() throws Exception {
        // Given
        Constant.messages = mock(I18N.class);
        model = mock(Model.class);
        extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        context = mock(Context.class);
        AutoDetectSessionManagementMethodType adsmt = new AutoDetectSessionManagementMethodType();
        AuthenticationMethod authMethod = mock(AuthenticationMethod.class);
        given(context.getSessionManagementMethod())
                .willReturn(adsmt.createSessionManagementMethod(1));
        given(context.getAuthenticationMethod()).willReturn(authMethod);
        given(authMethod.getAuthCheckingStrategy()).willReturn(mock(AuthCheckingStrategy.class));

        Control.initSingletonForTesting(model, extensionLoader);
        Model.setSingletonForTesting(model);

        Session session = mock(Session.class);
        given(session.getContextsForUrl(anyString())).willReturn(Arrays.asList(context));
        given(model.getSession()).willReturn(session);

        String body = "Response Body";
        String token = "12345678901234567890";
        HttpMessage msg =
                new HttpMessage(
                        new HttpRequestHeader(
                                "GET / HTTP/1.1\r\n"
                                        + "Header1: Value1\r\n"
                                        + "Header2: Value2\r\n"
                                        + "Authorization: "
                                        + token
                                        + "\r\n"
                                        + "Host: example.com\r\n\r\n"),
                        new HttpRequestBody("Request Body"),
                        new HttpResponseHeader("HTTP/1.1 200 OK\r\n"),
                        new HttpResponseBody(body));

        AuthUtils.recordSessionToken(
                new SessionToken(SessionToken.HEADER_SOURCE, "Authorization", token));
        PassiveScanData helper = mock(PassiveScanData.class);
        PassiveScanTaskHelper taskHelper = mock(PassiveScanTaskHelper.class);
        SessionDetectionScanRule rule = this.createScanner();
        rule.setHelper(helper);
        rule.setTaskHelper(taskHelper);

        // When
        rule.scanHttpResponseReceive(msg, 1, null);

        // Then
        ArgumentCaptor<SessionManagementMethod> captor =
                ArgumentCaptor.forClass(SessionManagementMethod.class);
        verify(context).setSessionManagementMethod(captor.capture());

        assertThat(captor.getValue(), instanceOf(HeaderBasedSessionManagementMethod.class));
        HeaderBasedSessionManagementMethod hbsmm =
                (HeaderBasedSessionManagementMethod) captor.getValue();
        assertThat(hbsmm.getHeaderConfigs().size(), is(equalTo(1)));
        assertThat(hbsmm.getHeaderConfigs().get(0).first, is(equalTo("Authorization")));
        assertThat(hbsmm.getHeaderConfigs().get(0).second, is(equalTo("{%header:Authorization%}")));
    }
}
