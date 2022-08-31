/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import net.htmlparser.jericho.Source;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.spider.SpiderParam;
import org.zaproxy.zap.model.DefaultValueGenerator;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.testutils.TestUtils;

/**
 * Class with helper/utility methods to help testing classes involving {@code SpiderParser}
 * implementations.
 *
 * @see org.zaproxy.zap.spider.parser.SpiderParser
 */
abstract class SpiderParserTestUtils<T extends SpiderParser> extends TestUtils {

    protected TestSpiderParserListener listener;
    protected SpiderParam spiderOptions;
    protected HttpMessage msg;
    protected ParseContext ctx;
    protected T parser;

    @BeforeEach
    void setup() {
        ctx = mock(ParseContext.class, withSettings().lenient());

        spiderOptions = mock(SpiderParam.class, withSettings().lenient());
        given(ctx.getSpiderParam()).willReturn(spiderOptions);

        ValueGenerator valueGenerator = new DefaultValueGenerator();
        given(ctx.getValueGenerator()).willReturn(valueGenerator);

        msg = new HttpMessage();
        given(ctx.getHttpMessage()).willReturn(msg);
        given(ctx.getPath())
                .willAnswer(
                        new CachedAnswer<>(
                                msg, msg -> msg.getRequestHeader().getURI().getEscapedPath()));
        given(ctx.getBaseUrl())
                .willAnswer(
                        new CachedAnswer<>(msg, msg -> msg.getRequestHeader().getURI().toString()));
        given(ctx.getSource())
                .willAnswer(
                        new CachedAnswer<>(
                                msg, msg -> new Source(msg.getResponseBody().toString())));

        parser = createParser();
        listener = createTestSpiderParserListener();
        parser.addSpiderParserListener(listener);
    }

    protected abstract T createParser();

    protected static String readFile(Path file) throws IOException {
        StringBuilder strBuilder = new StringBuilder();
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            strBuilder.append(line).append('\n');
        }
        return strBuilder.toString();
    }

    protected static TestSpiderParserListener createTestSpiderParserListener() {
        return new TestSpiderParserListener();
    }

    protected static class TestSpiderParserListener implements SpiderParserListener {

        private final List<SpiderResourceFound> resources;
        private final List<String> urls;

        private TestSpiderParserListener() {
            resources = new ArrayList<>();
            urls = new ArrayList<>();
        }

        int getNumberOfUrlsFound() {
            return urls.size();
        }

        List<String> getUrlsFound() {
            return urls;
        }

        int getNumberOfResourcesFound() {
            return resources.size();
        }

        List<SpiderResourceFound> getResourcesFound() {
            return resources;
        }

        @Override
        public void resourceFound(SpiderResourceFound resourceFound) {
            urls.add(resourceFound.getUri());
            resources.add(resourceFound);
        }

        boolean isResourceFound() {
            return false;
        }
    }

    static SpiderResourceFound uriResource(HttpMessage message, int depth, String uri) {
        return SpiderResourceFound.builder()
                .setMessage(message)
                .setDepth(depth)
                .setUri(uri)
                .build();
    }

    static SpiderResourceFound uriResource(
            HttpMessage message, int depth, String uri, boolean shouldIgnore) {
        return uriResource(message, depth, uri, shouldIgnore, new ArrayList<>());
    }

    static SpiderResourceFound uriResource(
            HttpMessage message,
            int depth,
            String uri,
            boolean shouldIgnore,
            List<HttpHeaderField> requestHeaders) {
        return SpiderResourceFound.builder()
                .setMessage(message)
                .setDepth(depth)
                .setUri(uri)
                .setShouldIgnore(shouldIgnore)
                .setHeaders(requestHeaders)
                .build();
    }

    static SpiderResourceFound postResource(
            HttpMessage message, int depth, String uri, String requestBody) {
        return postResource(message, depth, uri, requestBody, new ArrayList<>());
    }

    static SpiderResourceFound postResource(
            HttpMessage message,
            int depth,
            String uri,
            String requestBody,
            List<HttpHeaderField> requestHeaders) {
        return SpiderResourceFound.builder()
                .setMessage(message)
                .setDepth(depth)
                .setUri(uri)
                .setMethod(HttpRequestHeader.POST)
                .setBody(requestBody)
                .setHeaders(requestHeaders)
                .build();
    }

    static String params(String... params) {
        if (params == null || params.length == 0) {
            return "";
        }

        StringBuilder strBuilder = new StringBuilder();
        for (String param : params) {
            if (strBuilder.length() > 0) {
                strBuilder.append('&');
            }
            strBuilder.append(param);
        }
        return strBuilder.toString();
    }

    static String param(String name, String value) {
        try {
            return URLEncoder.encode(name, StandardCharsets.UTF_8.name())
                    + "="
                    + URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private static class CachedAnswer<T> implements Answer<T> {

        private final HttpMessage msg;
        private final Function<HttpMessage, T> provider;
        private T value;

        CachedAnswer(HttpMessage msg, Function<HttpMessage, T> provider) {
            this.msg = msg;
            this.provider = provider;
        }

        @Override
        public T answer(InvocationOnMock invocation) throws Throwable {
            if (value == null) {
                value = provider.apply(msg);
            }
            return value;
        }
    }
}
