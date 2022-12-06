/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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

import java.util.Objects;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.spider.SpiderParam;
import org.zaproxy.zap.model.ValueGenerator;

/**
 * A parse context.
 *
 * <p>Provides the data needed for parsing a HTTP message.
 */
public class ParseContext {

    private final SpiderParam spiderParam;
    private final ValueGenerator valueGenerator;
    private final HttpMessage httpMessage;
    private final String path;
    private final int depth;
    private String baseUrl;
    private Source source;

    /**
     * Constructs a {@code ParseContext} with the given values.
     *
     * @param spiderParam the spider options, must not be {@code null}.
     * @param valueGenerator the value generator, must not be {@code null}.
     * @param httpMessage the message, must not be {@code null}.
     * @param path the path of the HTTP message.
     * @param depth the current depth of the parsing.
     * @throws NullPointerException if any of {@code spiderParam}, {@code valueGenerator}, or {@code
     *     httpMessage} is {@code null}.
     */
    public ParseContext(
            SpiderParam spiderParam,
            ValueGenerator valueGenerator,
            HttpMessage httpMessage,
            String path,
            int depth) {
        this.spiderParam = Objects.requireNonNull(spiderParam);
        this.valueGenerator = Objects.requireNonNull(valueGenerator);
        this.httpMessage = Objects.requireNonNull(httpMessage);
        this.path = path;
        this.depth = depth;
    }

    /**
     * Gets the spider options.
     *
     * @return the options, never {@code null}.
     */
    public SpiderParam getSpiderParam() {
        return spiderParam;
    }

    /**
     * Gets the value generator.
     *
     * @return the value generator, never {@code null}.
     */
    public ValueGenerator getValueGenerator() {
        return valueGenerator;
    }

    /**
     * Gets the HTTP message.
     *
     * @return the message, never {@code null}.
     */
    public HttpMessage getHttpMessage() {
        return httpMessage;
    }

    /**
     * Gets the path of the HTTP message.
     *
     * @return the path, might be {@code null}.
     */
    public String getPath() {
        return path;
    }

    /**
     * Gets the current depth of the parsing.
     *
     * @return the depth.
     */
    public int getDepth() {
        return depth;
    }

    /**
     * Gets the URL of the HTTP message.
     *
     * @return the URL.
     */
    public String getBaseUrl() {
        if (baseUrl == null) {
            baseUrl = httpMessage.getRequestHeader().getURI().toString();
        }
        return baseUrl;
    }

    /**
     * Gets the {@code Source} with the response.
     *
     * @return the source.
     */
    public Source getSource() {
        if (source == null) {
            source = new Source(httpMessage.getResponseBody().toString());
        }
        return source;
    }
}
