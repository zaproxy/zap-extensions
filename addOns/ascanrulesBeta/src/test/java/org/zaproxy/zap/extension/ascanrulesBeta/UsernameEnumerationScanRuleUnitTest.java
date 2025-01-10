/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.mockito.MockSettings;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.authentication.FormBasedAuthenticationMethodType.FormBasedAuthenticationMethod;
import org.zaproxy.zap.extension.authentication.ExtensionAuthentication;
import org.zaproxy.zap.model.Context;

class UsernameEnumerationScanRuleUnitTest extends ActiveScannerTest<UsernameEnumerationScanRule> {

    private static final MockSettings LENIENT = withSettings().strictness(Strictness.LENIENT);

    private ExtensionAuthentication extAuth;
    private Session session;

    @Override
    protected UsernameEnumerationScanRule createScanner() {
        Model model = mock(Model.class, LENIENT);
        session = mock(Session.class, LENIENT);
        given(model.getSession()).willReturn(session);

        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, LENIENT);
        extAuth = mock(ExtensionAuthentication.class, LENIENT);
        given(extAuth.getModel()).willReturn(model);
        given(extensionLoader.getExtension(ExtensionAuthentication.class)).willReturn(extAuth);

        Control.initSingletonForTesting(model, extensionLoader);

        return new UsernameEnumerationScanRule();
    }

    @Override
    protected void shouldSendReasonableNumberOfMessages(
            AttackStrength strength, int maxNumberMessages, String defaultPath)
            throws HttpMalformedHeaderException {
        contextWithLoginUrl(defaultPath);
        super.shouldSendReasonableNumberOfMessages(strength, maxNumberMessages, defaultPath);
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(204)));
        assertThat(wasc, is(equalTo(13)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_IDNT_04_ACCOUNT_ENUMERATION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_IDNT_04_ACCOUNT_ENUMERATION.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_IDNT_04_ACCOUNT_ENUMERATION.getValue())));
    }

    @Test
    void shouldSkipIfNoContexts() throws Exception {
        // Given
        given(session.getContexts()).willReturn(List.of());
        rule.init(getHttpMessage(""), parent);
        // When
        rule.scan();
        // Then
        verify(parent).pluginSkipped(rule);
    }

    @Test
    void shouldSkipIfNoContextsWithFormBasedAuthenticationMethod() throws Exception {
        // Given
        Context context = mock(Context.class);
        given(session.getContexts()).willReturn(List.of(context));
        rule.init(getHttpMessage(""), parent);
        // When
        rule.scan();
        // Then
        verify(parent).pluginSkipped(rule);
    }

    @Test
    void shouldNotScanIfLoginUrlDoesNotMatchMessage() throws Exception {
        // Given
        contextWithLoginUrl("/login");
        HttpMessage msg = getHttpMessage("/not-login");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(0));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldScanMessageWithoutPath() throws Exception {
        // Given
        contextWithLoginUrl("");
        HttpMessage msg = getHttpMessage("");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(0)));
        assertThat(alertsRaised, hasSize(0));
    }

    private Context contextWithLoginUrl(String path) throws HttpMalformedHeaderException {
        Context context = mock(Context.class);
        FormBasedAuthenticationMethod authMethod = mock(FormBasedAuthenticationMethod.class);
        given(context.getAuthenticationMethod()).willReturn(authMethod);
        given(extAuth.getLoginRequestURIForContext(context))
                .willReturn(getHttpMessage(path).getRequestHeader().getURI());
        given(session.getContexts()).willReturn(List.of(context));
        given(session.getContextsForUrl(anyString())).willReturn(List.of(context));
        return context;
    }
}
