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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zaproxy.zap.model.StandardParameterParser;

class ClientUtilsUnitTest {

    private static final String EXAMPLE_COM = "https://www.example.com";
    private StandardParameterParser spp = new StandardParameterParser();

    @Nested
    class UrlToNodes {
        @Test
        void shouldFailIfNullUrl() {
            // Given / When
            IllegalArgumentException e =
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> ClientUtils.urlToNodes(null, spp));

            // Then
            assertThat(e.getMessage(), is("The url parameter should not be null"));
        }

        @Test
        void shouldFailIfNotUrl() {
            // Given / When
            IllegalArgumentException e =
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> ClientUtils.urlToNodes("example.com", spp));

            // Then
            assertThat(
                    e.getMessage(),
                    is(
                            "The url parameter must start with 'http://' or 'https://' - was example.com"));
        }

        @ParameterizedTest
        @ValueSource(strings = {EXAMPLE_COM, "http://www.example.com", "http://zap"})
        void shouldHandleBaseSiteNoSlash(String site) {
            // Given / When
            List<String> nodes = ClientUtils.urlToNodes(site, spp);

            // Then
            assertThat(nodes.size(), is(1));
            assertThat(nodes.get(0), is(site));
        }

        @Test
        void shouldHandleBaseSiteWithSlash() {
            // Given / When
            List<String> nodes = ClientUtils.urlToNodes(EXAMPLE_COM + "/", spp);

            // Then
            assertThat(nodes.size(), is(2));
            assertThat(nodes.get(0), is(EXAMPLE_COM));
            assertThat(nodes.get(1), is("/"));
        }

        @Test
        void shouldHandleBaseSiteNoSlashWithParams() {
            // Given / When
            List<String> nodes = ClientUtils.urlToNodes(EXAMPLE_COM + "?a=b", spp);

            // Then
            assertThat(nodes.size(), is(2));
            assertThat(nodes.get(0), is(EXAMPLE_COM));
            assertThat(nodes.get(1), is("(a)"));
        }

        @Test
        void shouldHandleBaseSiteWithSlashWithParams() {
            // Given / When
            List<String> nodes = ClientUtils.urlToNodes(EXAMPLE_COM + "/?a=b", spp);

            // Then
            assertThat(nodes.size(), is(2));
            assertThat(nodes.get(0), is(EXAMPLE_COM));
            assertThat(nodes.get(1), is("/(a)"));
        }

        @Test
        void shouldHandleSiteNoSlashWithFragment() {
            // Given / When
            List<String> nodes = ClientUtils.urlToNodes(EXAMPLE_COM + "#", spp);

            // Then
            assertThat(nodes.size(), is(2));
            assertThat(nodes.get(0), is(EXAMPLE_COM));
            assertThat(nodes.get(1), is("#"));
        }

        @ParameterizedTest
        @ValueSource(strings = {"f", "a=b", "a&b=c/d=f#f"})
        void shouldHandleBaseSiteNoSlashWithFragment(String fragment) {
            // Given / When
            List<String> nodes = ClientUtils.urlToNodes(EXAMPLE_COM + "#" + fragment, spp);

            // Then
            assertThat(nodes.size(), is(3));
            assertThat(nodes.get(0), is(EXAMPLE_COM));
            assertThat(nodes.get(1), is("#"));
            assertThat(nodes.get(2), is(fragment));
        }

        @Test
        void shouldHandleSiteWithSlashWithFragment() {
            // Given / When
            List<String> nodes = ClientUtils.urlToNodes(EXAMPLE_COM + "/#", spp);

            // Then
            assertThat(nodes.size(), is(2));
            assertThat(nodes.get(0), is(EXAMPLE_COM));
            assertThat(nodes.get(1), is("/#"));
        }

        @ParameterizedTest
        // Check fragments can contain any characters that are also significant in the
        // rest of the URL
        @ValueSource(strings = {"f", "a=b", "a&b=c/d=f#f"})
        void shouldHandleBaseSiteWithSlashWithFragment(String fragment) {
            // Given / When
            List<String> nodes = ClientUtils.urlToNodes(EXAMPLE_COM + "/#" + fragment, spp);

            // Then
            assertThat(nodes.size(), is(3));
            assertThat(nodes.get(0), is(EXAMPLE_COM));
            assertThat(nodes.get(1), is("/#"));
            assertThat(nodes.get(2), is(fragment));
        }

        @Test
        void shouldHandleUrlWithOnePathParamsFragment() {
            // Given / When
            List<String> nodes = ClientUtils.urlToNodes(EXAMPLE_COM + "/p?a=b#f", spp);

            // Then
            assertThat(nodes.size(), is(4));
            assertThat(nodes.get(0), is(EXAMPLE_COM));
            assertThat(nodes.get(1), is("p(a)"));
            assertThat(nodes.get(2), is("#"));
            assertThat(nodes.get(3), is("f"));
        }

        @Test
        void shouldHandleUrlWithTwoPathsParamsFragment() {
            // Given / When
            List<String> nodes = ClientUtils.urlToNodes(EXAMPLE_COM + "/p/q/r?a=b#f", spp);

            // Then
            assertThat(nodes.size(), is(6));
            assertThat(nodes.get(0), is(EXAMPLE_COM));
            assertThat(nodes.get(1), is("p"));
            assertThat(nodes.get(2), is("q"));
            assertThat(nodes.get(3), is("r(a)"));
            assertThat(nodes.get(4), is("#"));
            assertThat(nodes.get(5), is("f"));
        }

        @Test
        void shouldHandleUrlWithTwoPathsSlashParamsFragment() {
            // Given / When
            List<String> nodes = ClientUtils.urlToNodes(EXAMPLE_COM + "/p/q/r/?a=b#f", spp);

            // Then
            assertThat(nodes.size(), is(7));
            assertThat(nodes.get(0), is(EXAMPLE_COM));
            assertThat(nodes.get(1), is("p"));
            assertThat(nodes.get(2), is("q"));
            assertThat(nodes.get(3), is("r"));
            assertThat(nodes.get(4), is("/(a)"));
            assertThat(nodes.get(5), is("#"));
            assertThat(nodes.get(6), is("f"));
        }

        @Test
        void shouldHandleUrlWithTwoPathsSlashMultiParamsFragment() {
            // Given / When
            List<String> nodes = ClientUtils.urlToNodes(EXAMPLE_COM + "/p/q/r/?e=f&a=b&c#f", spp);

            // Then
            assertThat(nodes.size(), is(7));
            assertThat(nodes.get(0), is(EXAMPLE_COM));
            assertThat(nodes.get(1), is("p"));
            assertThat(nodes.get(2), is("q"));
            assertThat(nodes.get(3), is("r"));
            assertThat(nodes.get(4), is("/(a,c,e)"));
            assertThat(nodes.get(5), is("#"));
            assertThat(nodes.get(6), is("f"));
        }
    }

    @Nested
    class StripUrlFragment {

        @Test
        void shouldFailIfNullUrl() {
            // Given / When
            IllegalArgumentException e =
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> ClientUtils.stripUrlFragment(null));

            // Then
            assertThat(e.getMessage(), is("The url parameter should not be null"));
        }

        @ParameterizedTest
        @ValueSource(
                strings = {
                    EXAMPLE_COM + "#",
                    EXAMPLE_COM + "#/",
                    EXAMPLE_COM + "#/#/",
                    EXAMPLE_COM
                })
        void shouldStripFragment(String url) {
            // Given / When
            String strippedUrl = ClientUtils.stripUrlFragment(url);

            // Then
            assertThat(strippedUrl, is(EXAMPLE_COM));
        }
    }
}
