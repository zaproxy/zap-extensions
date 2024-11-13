/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.zest.ZestParam;
import org.zaproxy.zap.model.ParameterParser;
import org.zaproxy.zap.model.StandardParameterParser;
import org.zaproxy.zest.core.v1.ZestAssignFieldValue;
import org.zaproxy.zest.core.v1.ZestFieldDefinition;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestVariables;

/** Unit test for {@link DefaultRequestValueReplacer}. */
class DefaultRequestValueReplacerUnitTest {

    private Session session;
    private ZestScript script;
    private ZestParam conversionOptions;

    private RequestValueReplacer replacer;

    @BeforeEach
    void setup() {
        session = mock(Session.class);
        ParameterParser parser = new StandardParameterParser();
        given(session.getUrlParamParser(anyString())).willReturn(parser);
        given(session.getFormParamParser(anyString())).willReturn(parser);

        script = mock(ZestScript.class);
        ZestVariables parameters = mock();
        given(script.getParameters()).willReturn(parameters);
        given(parameters.getTokenStart()).willReturn("{{");
        given(parameters.getTokenEnd()).willReturn("}}");

        conversionOptions = mock(ZestParam.class);

        replacer = new DefaultRequestValueReplacer(session);
    }

    @Test
    void shouldReplaceFollowingQueryRequestValuesWithPreviousFormFields() throws Exception {
        // Given
        List<HttpMessage> messages = new ArrayList<>();
        HttpMessage msgStep1 = createHttpMessageWithForm();
        messages.add(msgStep1);
        HttpMessage msgStep2 = createHttpMessage();
        msgStep2.getRequestHeader().getURI().setEscapedQuery("a=token&x=UserValue&c=");
        messages.add(msgStep2);
        // When
        replacer.process(script, msgStep1, conversionOptions);
        ZestRequest request = replacer.process(script, msgStep2, conversionOptions);
        /// Then
        ArgumentCaptor<ZestAssignFieldValue> argCaptor =
                ArgumentCaptor.forClass(ZestAssignFieldValue.class);
        verify(script).add(argCaptor.capture());
        ZestAssignFieldValue fv = argCaptor.getValue();
        assertThat(fv.getVariableName(), is(equalTo("Msg1Form0Fielda")));
        ZestFieldDefinition fd = fv.getFieldDefinition();
        assertThat(fd.getFormIndex(), is(equalTo(0)));
        assertThat(fd.getFieldName(), is(equalTo("a")));
        assertThat(
                request.getUrlToken(),
                is(equalTo("http://example.com?a={{Msg1Form0Fielda}}&x=UserValue&c=")));
    }

    @Test
    void shouldReplaceFollowingBodyRequestValuesWithPreviousFormFields() throws Exception {
        // Given
        List<HttpMessage> messages = new ArrayList<>();
        HttpMessage msgStep1 = createHttpMessageWithForm();
        messages.add(msgStep1);
        HttpMessage msgStep2 = createHttpMessage();
        msgStep2.setRequestBody("a=token&x=UserValue&c=");
        messages.add(msgStep2);
        // When
        replacer.process(script, msgStep1, conversionOptions);
        replacer.process(script, msgStep2, conversionOptions);
        /// Then
        ArgumentCaptor<ZestAssignFieldValue> argCaptor =
                ArgumentCaptor.forClass(ZestAssignFieldValue.class);
        verify(script).add(argCaptor.capture());
        ZestAssignFieldValue fv = argCaptor.getValue();
        assertThat(fv.getVariableName(), is(equalTo("Msg1Form0Fielda")));
        ZestFieldDefinition fd = fv.getFieldDefinition();
        assertThat(fd.getFormIndex(), is(equalTo(0)));
        assertThat(fd.getFieldName(), is(equalTo("a")));
        assertThat(
                msgStep2.getRequestBody().toString(),
                is(equalTo("a={{Msg1Form0Fielda}}&x=UserValue&c=")));
    }

    private static HttpMessage createHttpMessageWithForm() throws Exception {
        HttpMessage message = createHttpMessage();
        message.setResponseBody(
                "<form><input type='hidden' name='a' value='token' /> <input type='text' name='x' value='y' /> <input type='text' name='c' value='' /> </form>");
        return message;
    }

    private static HttpMessage createHttpMessage() throws Exception {
        HttpMessage msg = new HttpMessage(new URI("http://example.com", true));
        msg.setResponseHeader("HTTP/1.1 200 OK");
        return msg;
    }
}
