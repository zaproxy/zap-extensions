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
package org.zaproxy.addon.client.internal;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.testutils.TestUtils;

class ClientMapWriterUnitTest extends TestUtils {

    private ClientNode root;
    private ClientMap map;

    @BeforeAll
    static void init() {
        mockMessages(new ExtensionClientIntegration());
    }

    @BeforeEach
    void setup() {
        Session session = mock(Session.class);
        root = new ClientNode(new ClientSideDetails("Root", ""), session);
        map = new ClientMap(root);
    }

    @AfterEach
    void tearDown() {
        ZAP.getEventBus().unregisterPublisher(map);
    }

    @Test
    void shouldExportExpectedSortedUrls() throws IOException {
        // Given
        String url = "https://example.com/";
        map.getOrAddNode(url, true, false);
        map.getOrAddNode(url + "zzz", true, false);
        map.getOrAddNode(url + "aaa", true, false);
        map.getOrAddNode(url + "zaa", true, false);
        Writer stringWriter = new StringWriter();
        // When
        ClientMapWriter.exportClientMap(stringWriter, map);
        // Then
        String output = stringWriter.toString();
        assertThat(
                output,
                is(
                        equalTo(
                                """
                                - node: "ClientMap"
                                  visited: false
                                  children:
                                  - node: "https://example.com"
                                    visited: false
                                    children:
                                    - node: "/"
                                    - node: "aaa"
                                    - node: "zaa"
                                    - node: "zzz"
                                """)));
    }

    @Test
    void shouldExportExpectedSortedUrlsAndComponents() throws IOException {
        // Given
        String zooUrl = "https://zoo.example.com";
        ClientNode zoo = map.getOrAddNode(zooUrl, true, false);
        // localStorage
        zoo.getUserObject()
                .addComponent(
                        new ClientSideComponent(
                                Map.of(),
                                "",
                                "some-sid",
                                "",
                                zooUrl,
                                "foo",
                                ClientSideComponent.Type.LOCAL_STORAGE,
                                "",
                                -1));
        zoo.getUserObject()
                .addComponent(
                        new ClientSideComponent(
                                Map.of(),
                                "",
                                "a-sid",
                                "",
                                zooUrl,
                                "foo",
                                ClientSideComponent.Type.LOCAL_STORAGE,
                                "",
                                -1));
        // sessionStorage
        zoo.getUserObject()
                .addComponent(
                        new ClientSideComponent(
                                Map.of(),
                                "",
                                "z-bar",
                                "",
                                zooUrl,
                                "fooz",
                                ClientSideComponent.Type.SESSION_STORAGE,
                                "",
                                -1));
        zoo.getUserObject()
                .addComponent(
                        new ClientSideComponent(
                                Map.of(),
                                "",
                                "z-bar",
                                "",
                                zooUrl,
                                "fooa",
                                ClientSideComponent.Type.SESSION_STORAGE,
                                "",
                                -1));
        zoo.getUserObject()
                .addComponent(
                        new ClientSideComponent(
                                Map.of(),
                                "",
                                "a-bar",
                                "",
                                zooUrl,
                                "fooa",
                                ClientSideComponent.Type.SESSION_STORAGE,
                                "",
                                -1));
        // Cookies
        zoo.getUserObject()
                .addComponent(
                        new ClientSideComponent(
                                Map.of(),
                                "",
                                "foo",
                                "",
                                zooUrl,
                                "aNotDisplayed",
                                ClientSideComponent.Type.COOKIES,
                                "",
                                -1));
        zoo.getUserObject()
                .addComponent(
                        new ClientSideComponent(
                                Map.of(),
                                "",
                                "foo",
                                "",
                                zooUrl,
                                "zNotDisplayed",
                                ClientSideComponent.Type.COOKIES,
                                "",
                                -1));
        zoo.getUserObject()
                .addComponent(
                        new ClientSideComponent(
                                Map.of(),
                                "",
                                "fooz",
                                "",
                                zooUrl,
                                "zNotDisplayed",
                                ClientSideComponent.Type.COOKIES,
                                "",
                                -1));
        // Links
        zoo.getUserObject()
                .addComponent(
                        new ClientSideComponent(
                                Map.of(),
                                "A",
                                "foo-logo",
                                "",
                                "https://foo.example.com/",
                                "",
                                ClientSideComponent.Type.LINK,
                                "",
                                -1));
        zoo.getUserObject()
                .addComponent(
                        new ClientSideComponent(
                                Map.of(),
                                "A",
                                "",
                                "",
                                "https://foo.example.com/",
                                "Foo Example",
                                ClientSideComponent.Type.LINK,
                                "",
                                -1));
        // Buttons
        zoo.getUserObject()
                .addComponent(
                        new ClientSideComponent(
                                Map.of(),
                                "BUTTON",
                                "",
                                "",
                                "",
                                "",
                                ClientSideComponent.Type.BUTTON,
                                "",
                                -1));
        // Inputs
        zoo.getUserObject()
                .addComponent(
                        new ClientSideComponent(
                                Map.of(),
                                "INPUT",
                                "",
                                "",
                                "",
                                "",
                                ClientSideComponent.Type.INPUT,
                                "",
                                0));
        // Forms
        zoo.getUserObject()
                .addComponent(
                        new ClientSideComponent(
                                Map.of(),
                                "FORM",
                                "head-search",
                                "",
                                "",
                                "",
                                ClientSideComponent.Type.FORM,
                                "",
                                0));
        zoo.getUserObject()
                .addComponent(
                        new ClientSideComponent(
                                Map.of(),
                                "FORM",
                                "foot-search",
                                "",
                                "",
                                "",
                                ClientSideComponent.Type.FORM,
                                "",
                                1));
        map.getOrAddNode("https://foo.example.com", true, false);
        map.getOrAddNode("https://1acme.example.com", true, false);

        String url = "https://example.com/";
        map.getOrAddNode(url, true, false);
        map.getOrAddNode(url + "zzz", true, false);
        map.getOrAddNode(url + "aaa", true, false);
        map.getOrAddNode(url + "zaa", true, false);

        Writer stringWriter = new StringWriter();
        // When
        ClientMapWriter.exportClientMap(stringWriter, map);
        // Then
        String output = stringWriter.toString();
        assertThat(
                output,
                is(
                        equalTo(
                                """
                                - node: "ClientMap"
                                  visited: false
                                  children:
                                  - node: "https://1acme.example.com"
                                  - node: "https://example.com"
                                    visited: false
                                    children:
                                    - node: "/"
                                    - node: "aaa"
                                    - node: "zaa"
                                    - node: "zzz"
                                  - node: "https://foo.example.com"
                                  - node: "https://zoo.example.com"
                                    components:
                                    - nodeType: "Button"
                                      href: ""
                                      text: ""
                                      id: ""
                                      tagName: "BUTTON"
                                      tagType: ""
                                    - nodeType: "Cookies"
                                      href: "https://zoo.example.com"
                                      id: "foo"
                                      tagName: ""
                                      tagType: ""
                                      storageEvent: true
                                    - nodeType: "Cookies"
                                      href: "https://zoo.example.com"
                                      id: "foo"
                                      tagName: ""
                                      tagType: ""
                                      storageEvent: true
                                    - nodeType: "Cookies"
                                      href: "https://zoo.example.com"
                                      id: "fooz"
                                      tagName: ""
                                      tagType: ""
                                      storageEvent: true
                                    - nodeType: "Form"
                                      href: ""
                                      text: ""
                                      id: "foot-search"
                                      tagName: "FORM"
                                      tagType: ""
                                      formId: 1
                                    - nodeType: "Form"
                                      href: ""
                                      text: ""
                                      id: "head-search"
                                      tagName: "FORM"
                                      tagType: ""
                                      formId: 0
                                    - nodeType: "Input"
                                      href: ""
                                      text: ""
                                      id: ""
                                      tagName: "INPUT"
                                      tagType: ""
                                      formId: 0
                                    - nodeType: "Link"
                                      href: "https://foo.example.com/"
                                      text: ""
                                      id: "foo-logo"
                                      tagName: "A"
                                      tagType: ""
                                    - nodeType: "Link"
                                      href: "https://foo.example.com/"
                                      text: "Foo Example"
                                      id: ""
                                      tagName: "A"
                                      tagType: ""
                                    - nodeType: "Local Storage"
                                      href: "https://zoo.example.com"
                                      id: "a-sid"
                                      tagName: ""
                                      tagType: ""
                                      storageEvent: true
                                    - nodeType: "Local Storage"
                                      href: "https://zoo.example.com"
                                      id: "some-sid"
                                      tagName: ""
                                      tagType: ""
                                      storageEvent: true
                                    - nodeType: "Session Storage"
                                      href: "https://zoo.example.com"
                                      id: "a-bar"
                                      tagName: ""
                                      tagType: ""
                                      storageEvent: true
                                    - nodeType: "Session Storage"
                                      href: "https://zoo.example.com"
                                      id: "z-bar"
                                      tagName: ""
                                      tagType: ""
                                      storageEvent: true
                                    - nodeType: "Session Storage"
                                      href: "https://zoo.example.com"
                                      id: "z-bar"
                                      tagName: ""
                                      tagType: ""
                                      storageEvent: true
                                """)));
    }
}
