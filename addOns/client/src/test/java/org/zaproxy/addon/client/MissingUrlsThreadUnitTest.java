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
package org.zaproxy.addon.client;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventPublisher;
import org.zaproxy.zap.model.StandardParameterParser;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.testutils.TestUtils;

class MissingUrlsThreadUnitTest extends TestUtils {

    private static final String AAA_URL = "https://aaa.example.com";
    private static final String CCC_URL = "https://ccc.example.com";

    private Model model;
    private Session session;
    private SiteMap siteMap;
    private ClientNode root;
    private ClientMap clientMap;

    @BeforeEach
    void setUp() throws Exception {
        setUpZap();

        model = mock(Model.class);
        session = mock(Session.class);
        siteMap = mock(SiteMap.class);
        StandardParameterParser ssp = new StandardParameterParser();
        given(session.getUrlParamParser(any(String.class))).willReturn(ssp);
        root = new ClientNode(new ClientSideDetails("Root", ""), session);
        clientMap = new ClientMap(root);
    }

    @AfterEach
    void tearDown() {
        ZAP.getEventBus().unregisterPublisher(clientMap);
    }

    @Test
    void shouldAddUrlInUnderStartNode() throws IOException {
        // Given
        given(model.getSession()).willReturn(session);
        given(session.getSiteTree()).willReturn(siteMap);

        clientMap.getOrAddNode(AAA_URL, false, false);

        EventPublisher evPub = mock(EventPublisher.class);
        Target target = new Target();
        target.setStartNode(new SiteNode(siteMap, 0, AAA_URL));
        Event event = new Event(evPub, "event", target);
        MissingUrlsThread mut = new MissingUrlsThread(model, event, clientMap.getRoot());

        HttpSender httpSender = mock(HttpSender.class);
        mut.setHttpSender(httpSender);

        // When
        mut.traverseMap(clientMap.getRoot());

        // Then
        verify(httpSender).sendAndReceive(any());
    }

    @Test
    void shouldNotAddUrlOutOfScope() throws IOException {
        // Given
        clientMap.getOrAddNode(AAA_URL + "/", false, false);

        EventPublisher evPub = mock(EventPublisher.class);
        Target target = new Target();
        target.setStartNode(new SiteNode(siteMap, 0, CCC_URL));
        Event event = new Event(evPub, "event", target);
        MissingUrlsThread mut = new MissingUrlsThread(model, event, clientMap.getRoot());

        HttpSender httpSender = mock(HttpSender.class);
        mut.setHttpSender(httpSender);

        // When
        mut.traverseMap(clientMap.getRoot());

        // Then
        verify(httpSender, times(0)).sendAndReceive(any());
    }

    @Test
    void shouldNotAddStorageNode() throws IOException {
        // Given
        clientMap.getOrAddNode(AAA_URL, false, true);

        EventPublisher evPub = mock(EventPublisher.class);
        Target target = new Target();
        target.setStartNode(new SiteNode(siteMap, 0, AAA_URL));
        Event event = new Event(evPub, "event", target);
        MissingUrlsThread mut = new MissingUrlsThread(model, event, clientMap.getRoot());

        HttpSender httpSender = mock(HttpSender.class);
        mut.setHttpSender(httpSender);

        // When
        mut.traverseMap(clientMap.getRoot());

        // Then
        verify(httpSender, times(0)).sendAndReceive(any());
    }

    @Test
    void shouldNotAddUrlIfNoScope() throws IOException {
        // Given
        clientMap.getOrAddNode(AAA_URL + "/", false, false);

        EventPublisher evPub = mock(EventPublisher.class);
        Event event = new Event(evPub, "event", new Target());
        MissingUrlsThread mut = new MissingUrlsThread(model, event, clientMap.getRoot());

        HttpSender httpSender = mock(HttpSender.class);
        mut.setHttpSender(httpSender);

        // When
        mut.traverseMap(clientMap.getRoot());

        // Then
        verify(httpSender, times(0)).sendAndReceive(any());
    }
}
