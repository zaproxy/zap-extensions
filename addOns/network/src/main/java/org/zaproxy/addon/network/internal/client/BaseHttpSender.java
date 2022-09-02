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
package org.zaproxy.addon.network.internal.client;

import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import org.apache.commons.httpclient.InvalidRedirectLocationException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.network.HttpRedirectionValidator;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.network.HttpSenderListener;
import org.zaproxy.zap.users.User;

/**
 * The base implementation of {@link CloseableHttpSenderImpl}.
 *
 * @param <T1> the type of the main context.
 * @param <T2> the type of the request context.
 * @param <T3> the type of the response body.
 */
public abstract class BaseHttpSender<T1 extends BaseHttpSenderContext, T2, T3>
        implements CloseableHttpSenderImpl<T1> {

    private static final Logger LOGGER = LogManager.getLogger(BaseHttpSender.class);

    private static final ThreadLocal<Boolean> IN_LISTENER = new ThreadLocal<>();

    private static final Comparator<HttpSenderListener> LISTENERS_COMPARATOR =
            (o1, o2) -> Integer.compare(o1.getListenerOrder(), o2.getListenerOrder());

    private static final HttpRequestConfig NO_REDIRECTS = HttpRequestConfig.builder().build();
    private static final HttpRequestConfig FOLLOW_REDIRECTS =
            HttpRequestConfig.builder().setFollowRedirects(true).build();

    private final List<HttpSenderListener> listeners;

    protected BaseHttpSender() {
        listeners = new ArrayList<>();
    }

    @Override
    public void addListener(HttpSenderListener listener) {
        Objects.requireNonNull(listener);
        listeners.add(listener);
        Collections.sort(listeners, LISTENERS_COMPARATOR);
    }

    @Override
    public void removeListener(HttpSenderListener listener) {
        Objects.requireNonNull(listener);
        listeners.remove(listener);
    }

    protected void notifyRequestListeners(T1 ctx, HttpMessage msg) {
        if (IN_LISTENER.get() != null) {
            return;
        }

        try {
            IN_LISTENER.set(true);
            for (HttpSenderListener listener : listeners) {
                try {
                    listener.onHttpRequestSend(msg, ctx.getInitiator(), ctx.getParent());
                } catch (Exception e) {
                    logErrorListener(listener, e);
                }
            }
        } finally {
            IN_LISTENER.remove();
        }
    }

    private static void logErrorListener(HttpSenderListener listener, Exception e) {
        LOGGER.error(
                "Error while notifying listener {} cause: {}",
                listener.getClass().getCanonicalName(),
                e.getMessage(),
                e);
    }

    protected void notifyResponseListeners(T1 ctx, HttpMessage msg) {
        if (IN_LISTENER.get() != null) {
            return;
        }

        try {
            IN_LISTENER.set(true);
            for (HttpSenderListener listener : listeners) {
                try {
                    listener.onHttpResponseReceive(msg, ctx.getInitiator(), ctx.getParent());
                } catch (Exception e) {
                    logErrorListener(listener, e);
                }
            }
        } finally {
            IN_LISTENER.remove();
        }
    }

    private final ResponseBodyConsumer<T3> defaultBodyConsumer =
            (msg, entity) -> {
                if (msg.isEventStream()) {
                    msg.getResponseBody().setCharset(msg.getResponseHeader().getCharset());
                    msg.getResponseBody().setLength(0);
                    return;
                }

                msg.setResponseBody(getBytes(entity));
            };

    protected abstract InputStream getStream(T3 body) throws IOException;

    protected abstract byte[] getBytes(T3 body) throws IOException;

    protected abstract T2 createRequestContext(T1 ctx, HttpRequestConfig requestConfig);

    @Override
    public void sendAndReceive(T1 ctx, HttpRequestConfig config, HttpMessage msg, Path file)
            throws IOException {
        HttpRequestConfig effectiveConfig = getEffectiveConfig(ctx, config);
        T2 requestCtx = createRequestContext(ctx, effectiveConfig);

        ResponseBodyConsumer<T3> bodyConsumer = defaultBodyConsumer;
        if (file != null) {
            bodyConsumer =
                    (message, body) -> {
                        if (effectiveConfig.isFollowRedirects()
                                && isRedirectionNeeded(
                                        message.getResponseHeader().getStatusCode())) {
                            defaultBodyConsumer.accept(message, body);
                            return;
                        }

                        HttpResponseHeader header = message.getResponseHeader();
                        try (FileChannel channel =
                                        (FileChannel)
                                                Files.newByteChannel(
                                                        file,
                                                        EnumSet.of(
                                                                StandardOpenOption.WRITE,
                                                                StandardOpenOption.CREATE,
                                                                StandardOpenOption
                                                                        .TRUNCATE_EXISTING));
                                InputStream is = getStream(body)) {
                            if (is == null) {
                                return;
                            }
                            long totalRead = 0;
                            while ((totalRead +=
                                            channel.transferFrom(
                                                    Channels.newChannel(is), totalRead, 1 << 24))
                                    < header.getContentLength()) ;
                        }
                    };
        }

        send(ctx, requestCtx, effectiveConfig, msg, bodyConsumer);
    }

    private HttpRequestConfig getEffectiveConfig(T1 ctx, HttpRequestConfig config) {
        if (config != null) {
            return config;
        }
        return ctx.isFollowRedirects() ? FOLLOW_REDIRECTS : NO_REDIRECTS;
    }

    /**
     * Helper method that sends the request of the given HTTP {@code message} with the given
     * configurations.
     *
     * <p>No redirections are followed (see {@link #followRedirections(HttpMessage,
     * HttpRequestConfig)}).
     *
     * @param message the message that will be sent.
     * @param requestConfig the request configurations.
     * @throws IOException if an error occurred while sending the message or following the
     *     redirections.
     */
    protected void send(
            T1 ctx,
            T2 requestCtx,
            HttpRequestConfig requestConfig,
            HttpMessage message,
            ResponseBodyConsumer<T3> responseBodyConsumer)
            throws IOException {
        sendNoRedirections(ctx, requestCtx, requestConfig, message, responseBodyConsumer, false);

        if (requestConfig.isFollowRedirects()) {
            followRedirections(ctx, requestCtx, requestConfig, message, responseBodyConsumer);
        }

        updateInitialMessage(ctx, requestCtx, message);

        if (requestConfig.isNotifyListeners()) {
            notifyResponseListeners(ctx, message);
        }
    }

    protected void updateInitialMessage(T1 ctx, T2 requestCtx, HttpMessage message) {}

    /**
     * Helper method that sends the request of the given HTTP {@code message} with the given
     * configurations.
     *
     * <p>No redirections are followed (see {@link #send(BaseHttpSenderContext, HttpRequestConfig,
     * HttpMessage, ResponseBodyConsumer)}).
     *
     * @param message the message that will be sent.
     * @param requestConfig the request configurations.
     * @throws IOException if an error occurred while sending the message or following the
     *     redirections.
     */
    private void sendNoRedirections(
            T1 ctx,
            T2 requestCtx,
            HttpRequestConfig requestConfig,
            HttpMessage message,
            ResponseBodyConsumer<T3> responseBodyConsumer,
            boolean notifyResponse)
            throws IOException {
        LOGGER.debug(
                "Sending {} {}",
                message.getRequestHeader().getMethod(),
                message.getRequestHeader().getURI());
        try {
            if (requestConfig.isNotifyListeners()) {
                notifyRequestListeners(ctx, message);
            }

            sendAuthenticated(ctx, requestCtx, requestConfig, message, responseBodyConsumer);

        } finally {
            LOGGER.debug(
                    "Received response after {}ms for {} {}",
                    message.getTimeElapsedMillis(),
                    message.getRequestHeader().getMethod(),
                    message.getRequestHeader().getURI());

            if (notifyResponse && requestConfig.isNotifyListeners()) {
                notifyResponseListeners(ctx, message);
            }
        }
    }

    private void sendAuthenticated(
            T1 ctx,
            T2 requestCtx,
            HttpRequestConfig requestConfig,
            HttpMessage message,
            ResponseBodyConsumer<T3> responseBodyConsumer)
            throws IOException {
        User user = ctx.getUser(message);
        if (user != null) {
            if (ctx.getInitiator() == HttpSender.AUTHENTICATION_POLL_INITIATOR) {
                user.processMessageToMatchAuthenticatedSession(message);
            } else if (ctx.getInitiator() != HttpSender.AUTHENTICATION_INITIATOR) {
                user.processMessageToMatchUser(message);
            }
        }

        LOGGER.debug("Sending message to: {}", message.getRequestHeader().getURI());
        sendImpl(ctx, requestCtx, requestConfig, message, responseBodyConsumer);

        if (user != null && isAuthenticationRequired(ctx, message, user)) {
            LOGGER.debug(
                    "First try to send authenticated message failed for {}. Authenticating and trying again...",
                    message.getRequestHeader().getURI());
            user.queueAuthentication(message);
            user.processMessageToMatchUser(message);
            sendImpl(ctx, requestCtx, requestConfig, message, responseBodyConsumer);
        } else {
            LOGGER.debug("SUCCESSFUL");
        }
    }

    private boolean isAuthenticationRequired(T1 ctx, HttpMessage message, User user) {
        return ctx.getInitiator() != HttpSender.AUTHENTICATION_INITIATOR
                && ctx.getInitiator() != HttpSender.AUTHENTICATION_POLL_INITIATOR
                && !message.getRequestHeader().isImage()
                && !user.isAuthenticated(message);
    }

    protected abstract void sendImpl(
            T1 ctx,
            T2 requestCtx,
            HttpRequestConfig requestConfig,
            HttpMessage message,
            ResponseBodyConsumer<T3> responseBodyConsumer)
            throws IOException;

    /**
     * Follows redirections using the response of the given {@code message}. The {@code validator}
     * in the given request configuration will be called for each redirection received. After the
     * call to this method the given {@code message} will have the contents of the last response
     * received (possibly the response of a redirection).
     *
     * <p>The validator is notified of each message sent and received (first message and
     * redirections followed, if any).
     *
     * @param message the message that will be sent, must not be {@code null}
     * @param requestConfig the request configuration that contains the validator responsible for
     *     validation of redirections, must not be {@code null}.
     * @throws IOException if an error occurred while sending the message or following the
     *     redirections
     * @see #isRedirectionNeeded(int)
     */
    protected void followRedirections(
            T1 ctx,
            T2 requestCtx,
            HttpRequestConfig requestConfig,
            HttpMessage message,
            ResponseBodyConsumer<T3> responseBodyConsumer)
            throws IOException {
        HttpRedirectionValidator validator = requestConfig.getRedirectionValidator();
        validator.notifyMessageReceived(message);

        User requestingUser = ctx.getUser(message);
        HttpMessage redirectMessage = message;
        int maxRedirections = ctx.getMaxRedirects();
        for (int i = 0;
                i < maxRedirections
                        && isRedirectionNeeded(redirectMessage.getResponseHeader().getStatusCode());
                i++) {
            URI newLocation = extractRedirectLocation(redirectMessage);
            if (newLocation == null || !validator.isValid(newLocation)) {
                return;
            }

            redirectMessage = redirectMessage.cloneAll();
            redirectMessage.setRequestingUser(requestingUser);
            redirectMessage.getRequestHeader().setURI(newLocation);

            if (isRequestRewriteNeeded(redirectMessage)) {
                redirectMessage.getRequestHeader().setMethod(HttpRequestHeader.GET);
                redirectMessage.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, null);
                redirectMessage.getRequestHeader().setHeader(HttpHeader.CONTENT_LENGTH, null);
                redirectMessage.setRequestBody("");
            }

            sendNoRedirections(
                    ctx, requestCtx, requestConfig, redirectMessage, responseBodyConsumer, true);
            validator.notifyMessageReceived(redirectMessage);

            // Update the response of the (original) message
            message.setResponseHeader(redirectMessage.getResponseHeader());
            message.setResponseBody(redirectMessage.getResponseBody());
        }
    }

    /**
     * Tells whether or not a redirection is needed based on the given status code.
     *
     * <p>A redirection is needed if the status code is 301, 302, 303, 307 or 308.
     *
     * @param statusCode the status code that will be checked
     * @return {@code true} if a redirection is needed, {@code false} otherwise
     * @see #isRequestRewriteNeeded(HttpMessage)
     */
    protected static boolean isRedirectionNeeded(int statusCode) {
        switch (statusCode) {
            case 301:
            case 302:
            case 303:
            case 307:
            case 308:
                return true;
            default:
                return false;
        }
    }

    /**
     * Tells whether or not the (original) request of the redirection, should be rewritten.
     *
     * <p>For status codes 301 and 302 the request should be changed from POST to GET when following
     * redirections, for status code 303 it should be changed to GET for all methods except GET/HEAD
     * (mimicking the behaviour of browsers, which per <a
     * href="https://tools.ietf.org/html/rfc7231#section-6.4">RFC 7231, Section 6.4</a> is now OK).
     *
     * @param message the message with the redirection.
     * @return {@code true} if the request should be rewritten, {@code false} otherwise
     * @see #isRedirectionNeeded(int)
     */
    private static boolean isRequestRewriteNeeded(HttpMessage message) {
        int statusCode = message.getResponseHeader().getStatusCode();
        String method = message.getRequestHeader().getMethod();
        if (statusCode == 301 || statusCode == 302) {
            return HttpRequestHeader.POST.equalsIgnoreCase(method);
        }
        return statusCode == 303
                && !(HttpRequestHeader.GET.equalsIgnoreCase(method)
                        || HttpRequestHeader.HEAD.equalsIgnoreCase(method));
    }

    /**
     * Extracts a {@code URI} from the {@code Location} header of the given HTTP {@code message}.
     *
     * <p>If there's no {@code Location} header this method returns {@code null}.
     *
     * @param message the HTTP message that will processed
     * @return the {@code URI} created from the value of the {@code Location} header, might be
     *     {@code null}
     * @throws InvalidRedirectLocationException if the value of {@code Location} header is not a
     *     valid {@code URI}
     */
    private static URI extractRedirectLocation(HttpMessage message)
            throws InvalidRedirectLocationException {
        String location = message.getResponseHeader().getHeader(HttpHeader.LOCATION);
        if (location == null) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("No Location header found: " + message.getResponseHeader());
            }
            return null;
        }

        try {
            return new URI(message.getRequestHeader().getURI(), location, true);
        } catch (URIException ex) {
            try {
                // Handle redirect URLs that are unencoded
                return new URI(message.getRequestHeader().getURI(), location, false);
            } catch (URIException e) {
                throw new InvalidRedirectLocationException(
                        "Invalid redirect location: " + location, location, ex);
            }
        }
    }
}
