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
package org.zaproxy.addon.spider;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.net.ssl.SSLException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.spider.filters.ParseFilter;
import org.zaproxy.addon.spider.filters.ParseFilter.FilterResult;
import org.zaproxy.addon.spider.parser.ParseContext;
import org.zaproxy.addon.spider.parser.SpiderParser;
import org.zaproxy.addon.spider.parser.SpiderResourceFound;

/** The SpiderTask representing a spidering task performed during the Spidering process. */
public class SpiderTask implements Runnable {

    private static final List<String> METHODS_WITHOUT_CONTENT_LENGTH =
            List.of(
                    HttpRequestHeader.GET,
                    HttpRequestHeader.CONNECT,
                    HttpRequestHeader.DELETE,
                    HttpRequestHeader.HEAD,
                    HttpRequestHeader.TRACE);

    /** The parent spider. */
    private Spider parent;

    /**
     * The history reference to the database record where the request message has been partially
     * filled in.
     *
     * <p>Might be {@code null} if failed to create or persist the message, if the task was already
     * executed or if a clean up was performed.
     *
     * @see #cleanup()
     * @see #deleteHistoryReference()
     * @see #prepareHttpMessage()
     */
    private HistoryReference reference;

    /** The spider resource found. */
    private SpiderResourceFound resourceFound;

    private ExtensionHistory extHistory;

    /** The Constant log. */
    private static final Logger LOGGER = LogManager.getLogger(SpiderTask.class);

    /**
     * Instantiates a new spider task using the target URI. The purpose of this task is to crawl the
     * given uri, using the provided method and supplied request headers, find any other uris in the
     * fetched resource and create other tasks.
     *
     * <p>The body of the request message is also provided in the {@literal requestBody} parameter
     * and will be used when fetching the resource from the specified uri.
     *
     * @param parent the spider controlling the crawling process
     * @param resourceFound the spider resource found
     * @param uri the uri that this task should process
     */
    public SpiderTask(Spider parent, SpiderResourceFound resourceFound, URI uri) {
        super();
        this.parent = parent;
        this.resourceFound = resourceFound;

        LOGGER.debug("New task submitted for uri: {}", uri);

        // Create a new HttpMessage that will be used for the request and persist it in the database
        // using HistoryReference
        try {
            HttpRequestHeader requestHeader =
                    new HttpRequestHeader(
                            resourceFound.getMethod(), uri, resourceFound.getHttpVersion());
            // Intentionally adding supplied request headers before the referer header
            // to prioritize "send referer header" option
            for (HttpHeaderField header : resourceFound.getHeaders()) {
                requestHeader.addHeader(header.getName(), header.getValue());
            }
            if (resourceFound.getMessage() != null
                    && parent.getSpiderParam().isSendRefererHeader()) {
                requestHeader.setHeader(
                        HttpRequestHeader.REFERER,
                        resourceFound.getMessage().getRequestHeader().getURI().toString());
            }
            HttpMessage msg = new HttpMessage(requestHeader);
            int bodyLength = resourceFound.getBody().length();
            String method = resourceFound.getMethod();
            if (bodyLength == 0
                    && METHODS_WITHOUT_CONTENT_LENGTH.stream()
                            .anyMatch(aMethod -> aMethod.equalsIgnoreCase(method))) {
                msg.getRequestHeader().setHeader(HttpHeader.CONTENT_LENGTH, null);
            } else {
                msg.getRequestHeader().setContentLength(bodyLength);
                msg.setRequestBody(resourceFound.getBody());
            }
            this.reference =
                    new HistoryReference(
                            parent.getModel().getSession(), HistoryReference.TYPE_SPIDER_TASK, msg);
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error("Error while building HttpMessage for uri: {}", uri, e);
        } catch (DatabaseException e) {
            LOGGER.error("Error while persisting HttpMessage for uri: {}", uri, e);
        }
    }

    @Override
    public void run() {
        try {
            if (reference == null) {
                LOGGER.warn("Null URI. Skipping crawling task: {}", this);
                return;
            }

            LOGGER.debug(
                    "Spider Task Started. Processing uri at depth {} using already constructed message: {}",
                    resourceFound.getDepth(),
                    reference.getURI());

            runImpl();
        } finally {
            parent.postTaskExecution();
            LOGGER.debug("Spider Task finished.");
        }
    }

    private void runImpl() {
        // Check if the should stop
        if (parent.isStopped()) {
            LOGGER.debug("Spider process is stopped. Skipping crawling task...");
            deleteHistoryReference();
            return;
        }

        // Check if the crawling process is paused and do any "before execution" processing
        parent.preTaskExecution();

        // Fetch the resource
        HttpMessage msg;
        try {
            msg = prepareHttpMessage();
        } catch (Exception e) {
            LOGGER.error("Failed to prepare HTTP message: ", e);
            return;
        }

        try {
            fetchResource(msg);
        } catch (Exception e) {
            setErrorResponse(msg, e);
            parent.notifyListenersSpiderTaskResult(
                    new SpiderTaskResult(msg, getSkippedMessage("ioerror")));
            return;
        }

        // Check if the should stop
        if (parent.isStopped()) {
            parent.notifyListenersSpiderTaskResult(
                    new SpiderTaskResult(msg, getSkippedMessage("stopped")));
            LOGGER.debug("Spider process is stopped. Skipping crawling task...");
            return;
        }
        // Check if the crawling process is paused
        parent.checkPauseAndWait();

        // Check the parse filters to see if the resource should be skipped from parsing
        FilterResult filterResult = FilterResult.NOT_FILTERED;
        boolean wanted = false;
        for (ParseFilter filter : parent.getController().getParseFilters()) {
            filterResult = filter.filtered(msg);
            if (filterResult.isFiltered()) {
                break;
            } else if (filterResult == FilterResult.WANTED) wanted = true;
        }
        if (!wanted && !filterResult.isFiltered()) {
            filterResult = parent.getController().getDefaultParseFilter().filtered(msg);
        }
        if (filterResult.isFiltered()) {
            LOGGER.debug(
                    "Resource [{}] fetched, but will not be parsed due to a ParseFilter rule: {}",
                    msg.getRequestHeader().getURI(),
                    filterResult.getReason());

            parent.notifyListenersSpiderTaskResult(
                    new SpiderTaskResult(msg, filterResult.getReason()));
            return;
        }

        // Check if the should stop
        if (parent.isStopped()) {
            parent.notifyListenersSpiderTaskResult(
                    new SpiderTaskResult(msg, getSkippedMessage("stopped")));
            LOGGER.debug("Spider process is stopped. Skipping crawling task...");
            return;
        }
        // Check if the crawling process is paused
        parent.checkPauseAndWait();

        int maxDepth = parent.getSpiderParam().getMaxDepth();
        if (maxDepth == SpiderParam.UNLIMITED_DEPTH || resourceFound.getDepth() < maxDepth) {
            parent.notifyListenersSpiderTaskResult(new SpiderTaskResult(msg));
            processResource(parent, resourceFound.getDepth(), msg);
        } else {
            parent.notifyListenersSpiderTaskResult(
                    new SpiderTaskResult(msg, getSkippedMessage("maxdepth")));
        }
    }

    private String getSkippedMessage(String key) {
        return parent.getExtensionSpider()
                .getMessages()
                .getString("spider.task.message.skipped." + key);
    }

    /**
     * Prepares the HTTP message to be sent to the target server.
     *
     * <p>The HTTP message is read from the database and set up with common headers (e.g.
     * User-Agent) and properties (e.g. user).
     *
     * @return the HTTP message
     * @throws HttpMalformedHeaderException if an error occurred while parsing the HTTP message read
     *     from the database
     * @throws DatabaseException if an error occurred while reading the HTTP message from the
     *     database
     */
    private HttpMessage prepareHttpMessage()
            throws HttpMalformedHeaderException, DatabaseException {
        // Build fetch the request message from the database
        HttpMessage msg;
        try {
            msg = reference.getHttpMessage();
            // HistoryReference is about to be deleted, so no point keeping referencing it.
            msg.setHistoryRef(null);
        } finally {
            deleteHistoryReference();
        }

        msg.getRequestHeader().setHeader(HttpHeader.IF_MODIFIED_SINCE, null);
        msg.getRequestHeader().setHeader(HttpHeader.IF_NONE_MATCH, null);

        // Check if there is a custom user agent
        if (parent.getSpiderParam().getUserAgent() != null) {
            msg.getRequestHeader()
                    .setHeader(HttpHeader.USER_AGENT, parent.getSpiderParam().getUserAgent());
        }

        // Check if there's a need to send the message from the point of view of a User
        if (parent.getScanUser() != null) {
            msg.setRequestingUser(parent.getScanUser());
        }
        return msg;
    }

    /**
     * Deletes the history reference, should be called when no longer needed.
     *
     * <p>The call to this method has no effect if the history reference no longer exists (i.e.
     * {@code null}).
     *
     * @see #reference
     */
    private void deleteHistoryReference() {
        if (reference == null) {
            return;
        }

        if (getExtensionHistory() != null) {
            getExtensionHistory().delete(reference);
            reference = null;
        }
    }

    private void setErrorResponse(HttpMessage msg, Exception cause) {
        StringBuilder strBuilder = new StringBuilder(250);
        if (cause instanceof SSLException) {
            strBuilder.append(Constant.messages.getString("network.ssl.error.connect"));
            strBuilder.append(msg.getRequestHeader().getURI().toString()).append('\n');
            strBuilder
                    .append(Constant.messages.getString("network.ssl.error.exception"))
                    .append(cause.getMessage())
                    .append('\n');
            strBuilder
                    .append(Constant.messages.getString("network.ssl.error.exception.rootcause"))
                    .append(ExceptionUtils.getRootCauseMessage(cause))
                    .append('\n');
            strBuilder.append(
                    Constant.messages.getString(
                            "network.ssl.error.help",
                            Constant.messages.getString("network.ssl.error.help.url")));

            strBuilder.append("\n\nStack Trace:\n");
            for (String stackTraceFrame : ExceptionUtils.getRootCauseStackTrace(cause)) {
                strBuilder.append(stackTraceFrame).append('\n');
            }
        } else {
            strBuilder
                    .append(cause.getClass().getName())
                    .append(": ")
                    .append(cause.getLocalizedMessage())
                    .append("\n\nStack Trace:\n");
            for (String stackTraceFrame : ExceptionUtils.getRootCauseStackTrace(cause)) {
                strBuilder.append(stackTraceFrame).append('\n');
            }
        }

        String message = strBuilder.toString();

        HttpResponseHeader responseHeader;
        try {
            responseHeader = new HttpResponseHeader("HTTP/1.1 400 ZAP IO Error");
            responseHeader.setHeader(HttpHeader.CONTENT_TYPE, "text/plain; charset=UTF-8");
            responseHeader.setHeader(
                    HttpHeader.CONTENT_LENGTH,
                    Integer.toString(message.getBytes(StandardCharsets.UTF_8).length));
            msg.setResponseHeader(responseHeader);
            msg.setResponseBody(message);
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error("Failed to create error response:", e);
        }
    }

    /**
     * Process a resource, searching for links (uris) to other resources.
     *
     * @param message the HTTP Message
     */
    static void processResource(Spider parent, int depth, HttpMessage message) {
        List<SpiderParser> parsers = parent.getController().getParsers();

        // Get the full path of the file
        String path = null;
        try {
            path = message.getRequestHeader().getURI().getPath();
        } catch (URIException e) {
        } finally {
            // Handle null paths.
            if (path == null) path = "";
        }

        ParseContext ctx =
                new ParseContext(
                        parent.getSpiderParam(),
                        parent.getExtensionSpider().getValueGenerator(),
                        message,
                        path,
                        depth);
        boolean alreadyConsumed = false;
        for (SpiderParser parser : parsers) {
            try {
                alreadyConsumed |= parse(ctx, alreadyConsumed, parser, path);
            } catch (Exception e) {
                LOGGER.error(
                        "An error occurred while parsing the resource [{}] with [{}]: {}",
                        path,
                        parser.getClass(),
                        e.getMessage(),
                        e);
            }
        }
    }

    private static boolean parse(
            ParseContext ctx, boolean alreadyConsumed, SpiderParser parser, String path) {
        if (!parser.canParseResource(ctx, alreadyConsumed)) {
            LOGGER.debug("Parser {} cannot parse resource '{}'", parser, path);
            return false;
        }

        LOGGER.debug("Parser {} can parse resource '{}'", parser, path);
        return parser.parseResource(ctx);
    }

    private ExtensionHistory getExtensionHistory() {
        if (this.extHistory == null) {
            this.extHistory =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionHistory.class);
        }
        return this.extHistory;
    }

    /**
     * Fetches a resource.
     *
     * @param msg the HTTP message that will be sent to the server
     * @throws IOException Signals that an I/O exception has occurred.
     */
    private void fetchResource(HttpMessage msg) throws IOException {
        if (parent.getHttpSender() == null) {
            return;
        }

        try {
            parent.getHttpSender().sendAndReceive(msg);
        } catch (ConnectException e) {
            LOGGER.debug("Failed to connect to: {}", msg.getRequestHeader().getURI(), e);
            throw e;
        } catch (SocketTimeoutException e) {
            LOGGER.debug("Socket timeout: {}", msg.getRequestHeader().getURI(), e);
            throw e;
        } catch (SocketException e) {
            LOGGER.debug("Socket exception: {}", msg.getRequestHeader().getURI(), e);
            throw e;
        } catch (UnknownHostException e) {
            LOGGER.debug("Unknown host: {}", msg.getRequestHeader().getURI(), e);
            throw e;
        } catch (Exception e) {
            LOGGER.error(
                    "An error occurred while fetching the resource [{}]: {}",
                    msg.getRequestHeader().getURI(),
                    e.getMessage(),
                    e);
            throw e;
        }
    }

    /**
     * Cleans up the resources used by the task.
     *
     * <p>Should be called if the task was not executed.
     */
    void cleanup() {
        deleteHistoryReference();
    }
}
