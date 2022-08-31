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
package org.zaproxy.addon.spider.parser;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.Mockito.mock;

import net.htmlparser.jericho.Source;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.spider.parser.SpiderParserUnitTest.TestSpiderParser;

/** Unit test for {@link SpiderParser}. */
class SpiderParserUnitTest extends SpiderParserTestUtils<TestSpiderParser> {

    @Override
    protected TestSpiderParser createParser() {
        return new TestSpiderParser();
    }

    @Test
    void shouldHaveNonNullLogger() {
        assertThat(parser.getLogger(), is(not(nullValue())));
    }

    @Test
    void shouldNotifyListenersOfResourceFound() {
        // Given
        TestSpiderParserListener listener2 = createTestSpiderParserListener();
        SpiderResourceFound resourceFound1 = mock(SpiderResourceFound.class);
        SpiderResourceFound resourceFound2 = mock(SpiderResourceFound.class);
        // When
        parser.addSpiderParserListener(listener2);
        parser.notifyListenersResourceFound(resourceFound1);
        parser.notifyListenersResourceFound(resourceFound2);
        // Then
        assertThat(listener.getResourcesFound(), contains(resourceFound1, resourceFound2));
        assertThat(listener2.getResourcesFound(), contains(resourceFound1, resourceFound2));
    }

    @Test
    void shouldNotNotifyRemovedListenerOfResourceFound() {
        // Given
        TestSpiderParserListener listener2 = createTestSpiderParserListener();
        parser.addSpiderParserListener(listener2);
        SpiderResourceFound resourceFound1 = mock(SpiderResourceFound.class);
        SpiderResourceFound resourceFound2 = mock(SpiderResourceFound.class);
        // When
        parser.notifyListenersResourceFound(resourceFound1);
        parser.removeSpiderParserListener(listener2);
        parser.notifyListenersResourceFound(resourceFound2);
        // Then
        assertThat(listener.getResourcesFound(), contains(resourceFound1, resourceFound2));
        assertThat(listener2.getResourcesFound(), contains(resourceFound1));
    }

    @Test
    void shouldNotifyListenersOfProcessedUrl() {
        // Given
        int depth = 42;
        String baseUrl = "https://example.com/";
        String localUrl = "/path/";
        String expectedUri = "https://example.com/path/";
        // When
        parser.processUrl(msg, depth, localUrl, baseUrl);
        // Then
        assertThat(
                listener.getResourcesFound(), contains(uriResource(msg, depth + 1, expectedUri)));
    }

    @Test
    void shouldNotNotifyListenersOfMalformedProcessedUrl() {
        // Given
        int depth = 42;
        String baseUrl = "/";
        String localUrl = "/";
        // When
        parser.processUrl(msg, depth, localUrl, baseUrl);
        // Then
        assertThat(listener.getResourcesFound(), is(empty()));
    }

    protected static class TestSpiderParser extends SpiderParser {

        @Override
        public boolean parseResource(HttpMessage message, Source source, int depth) {
            return true;
        }

        @Override
        public boolean canParseResource(
                HttpMessage message, String path, boolean wasAlreadyConsumed) {
            return true;
        }
    }
}
