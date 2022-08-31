/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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

import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.spider.UrlCanonicalizer;

/**
 * The Abstract Class SpiderParser is the base for parsers used by the spider. The main purpose of
 * these Parsers is to find links (uris) to resources in the provided content. Uses the Jericho
 * Library for parsing.
 */
public abstract class SpiderParser {

    /** The listeners to spider parsing events. */
    private List<SpiderParserListener> listeners = new LinkedList<>();

    private final Logger logger = LogManager.getLogger(getClass());

    /**
     * Gets the logger.
     *
     * @return the logger, never {@code null}.
     */
    protected Logger getLogger() {
        return logger;
    }

    /**
     * Adds a listener to spider parsing events.
     *
     * @param listener the listener
     */
    public void addSpiderParserListener(SpiderParserListener listener) {
        listeners.add(listener);
    }

    /**
     * Removes a listener to spider parsing events.
     *
     * @param listener the listener
     */
    public void removeSpiderParserListener(SpiderParserListener listener) {
        this.listeners.remove(listener);
    }

    /**
     * Notify the listeners that a resource was found.
     *
     * @param resourceFound the resource found.
     */
    protected void notifyListenersResourceFound(SpiderResourceFound resourceFound) {
        for (SpiderParserListener l : listeners) {
            l.resourceFound(resourceFound);
        }
    }

    protected void processUrl(ParseContext ctx, String localUrl) {
        processUrl(ctx, localUrl, ctx.getBaseUrl());
    }

    protected void processUrl(ParseContext ctx, String localUrl, String baseUrl) {
        processUrl(ctx, ctx.getHttpMessage(), ctx.getDepth(), localUrl, baseUrl);
    }

    protected String getCanonicalUrl(ParseContext ctx, String localUrl, String baseUrl) {
        return UrlCanonicalizer.getCanonicalUrl(ctx, localUrl, baseUrl);
    }

    /**
     * Builds an url and notifies the listeners.
     *
     * @param message the message
     * @param depth the depth
     * @param localURL the local url
     * @param baseUrl the base url
     */
    private void processUrl(
            ParseContext ctx, HttpMessage message, int depth, String localURL, String baseUrl) {
        // Build the absolute canonical URL
        String fullURL = getCanonicalUrl(ctx, localURL, baseUrl);
        if (fullURL == null) {
            return;
        }

        getLogger().debug("Canonical URL constructed using '{}': {}", localURL, fullURL);
        notifyListenersResourceFound(
                SpiderResourceFound.builder()
                        .setMessage(message)
                        .setDepth(depth + 1)
                        .setUri(fullURL)
                        .build());
    }

    /**
     * Parses the resource. The HTTP message containing the request and the response is given. Also,
     * if possible, a Jericho source with the Response Body is provided through the context.
     *
     * <p>When a link is encountered, implementations can use one of the {@code processUrl} methods
     * and {@link #notifyListenersResourceFound(SpiderResourceFound)} to announce the found URIs.
     *
     * <p>The return value specifies whether the resource should be considered 'completely
     * processed'/consumed and should be treated accordingly by subsequent parsers. For example, any
     * parsers which are meant to be 'fall-back' parsers should skip messages already processed by
     * other parsers.
     *
     * @param ctx the parse context.
     * @return whether the resource is considered to be exhaustively processed
     */
    public abstract boolean parseResource(ParseContext ctx);

    /**
     * Checks whether the parser should be called to parse the given HttpMessage.
     *
     * <p>Based on the specifics of the HttpMessage and whether this message was already processed
     * by another Parser, this method should decide whether the {@link #parseResource(ParseContext)}
     * should be invoked.
     *
     * <p>The {@code wasAlreadyConsumed} could be used by parsers which represent a 'fall-back'
     * parser to check whether any other parser has processed the message before.
     *
     * @param ctx the parse context.
     * @param wasAlreadyConsumed if the resource was already parsed by another SpiderParser
     * @return true, if the {@link #parseResource(ParseContext ctx)} should be invoked.
     */
    public abstract boolean canParseResource(ParseContext ctx, boolean wasAlreadyConsumed);
}
