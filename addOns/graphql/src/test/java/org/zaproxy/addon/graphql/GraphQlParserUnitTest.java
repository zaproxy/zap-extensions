/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.graphql;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.util.Locale;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.testutils.StaticContentServerHandler;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;

class GraphQlParserUnitTest extends TestUtils {

    String endpointUrl;

    @BeforeEach
    void setup() throws Exception {
        setUpZap();
        startServer();
        endpointUrl = "http://localhost:" + nano.getListeningPort();
        Constant.messages = new I18N(Locale.ENGLISH);
    }

    @AfterEach
    void teardown() throws Exception {
        stopServer();
    }

    @Test
    void shouldFailIntrospectionWhenResponseIsEmpty() throws Exception {
        // Given
        nano.addHandler(new StaticContentServerHandler("/", ""));
        GraphQlParser gqp = new GraphQlParser(endpointUrl);
        // When/Then
        assertThrows(IOException.class, gqp::introspect);
    }

    @Test
    void shouldFailIntrospectionWhenResponseIsNotJson() throws Exception {
        // Given
        nano.addHandler(new StaticContentServerHandler("/", "not json"));
        GraphQlParser gqp = new GraphQlParser(endpointUrl);
        // When/Then
        assertThrows(IOException.class, gqp::introspect);
    }

    @Test
    void shouldFailIntrospectionWhenResponseDataIsNull() throws Exception {
        // Given
        nano.addHandler(new StaticContentServerHandler("/", "{\"data\": null}"));
        GraphQlParser gqp = new GraphQlParser(endpointUrl);
        // When/Then
        assertThrows(IOException.class, gqp::introspect);
    }

    @Test
    void shouldRaiseAlertWhenSpecified() throws Exception {
        // Given
        String introspectionResponse =
                "{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Root\"},\"types\":[{\"kind\":\"OBJECT\",\"name\":\"Root\",\"fields\":[{\"name\":\"zap\",\"args\":[],\"type\":{\"kind\":\"SCALAR\",\"name\":\"String\"}}]}]}}}";
        nano.addHandler(new StaticContentServerHandler("/", introspectionResponse));
        GraphQlParser gqp = new GraphQlParser(endpointUrl);
        var extAlert = mock(ExtensionAlert.class);
        Control.getSingleton().getExtensionLoader().addExtension(extAlert);
        // When
        gqp.introspect(true);
        // Then
        var alert = ArgumentCaptor.forClass(Alert.class);
        verify(extAlert).alertFound(alert.capture(), any());
        assertThat(alert.getValue().getPluginId(), is(ExtensionGraphQl.TOOL_ALERT_ID));
        assertThat(alert.getValue().getAlertRef(), is(ExtensionGraphQl.TOOL_ALERT_ID + "-1"));
        assertThat(alert.getValue().getName(), is("!graphql.introspection.alert.name!"));
    }
}
