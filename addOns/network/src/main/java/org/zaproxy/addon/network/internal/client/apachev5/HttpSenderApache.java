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
package org.zaproxy.addon.network.internal.client.apachev5;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.function.Supplier;
import org.apache.commons.httpclient.URI;
import org.apache.hc.client5.http.auth.AuthSchemeFactory;
import org.apache.hc.client5.http.auth.StandardAuthScheme;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.config.TlsConfig;
import org.apache.hc.client5.http.cookie.CookieStore;
import org.apache.hc.client5.http.cookie.StandardCookieSpec;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.CustomH2AsyncClientCreator;
import org.apache.hc.client5.http.impl.auth.BasicSchemeFactory;
import org.apache.hc.client5.http.impl.auth.DigestSchemeFactory;
import org.apache.hc.client5.http.impl.auth.KerberosSchemeFactory;
import org.apache.hc.client5.http.impl.auth.NTLMSchemeFactory;
import org.apache.hc.client5.http.impl.auth.SPNegoSchemeFactory;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CustomHttpClientCreator;
import org.apache.hc.client5.http.impl.classic.ZapProtocolExec;
import org.apache.hc.client5.http.impl.classic.ZapRequestAddCookies;
import org.apache.hc.client5.http.impl.io.ManagedHttpClientConnectionFactory;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.ZapHttpClientConnectionOperator;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.client5.http.protocol.ResponseProcessCookies;
import org.apache.hc.client5.http.socket.LayeredConnectionSocketFactory;
import org.apache.hc.core5.concurrent.FutureCallback;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ConnectionClosedException;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.HttpVersion;
import org.apache.hc.core5.http.MessageHeaders;
import org.apache.hc.core5.http.ProtocolVersion;
import org.apache.hc.core5.http.config.CharCodingConfig;
import org.apache.hc.core5.http.config.Lookup;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.http.io.HttpClientConnection;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.message.BasicClassicHttpRequest;
import org.apache.hc.core5.http.message.BasicHttpRequest;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.http.protocol.HttpProcessor;
import org.apache.hc.core5.http.protocol.HttpProcessorBuilder;
import org.apache.hc.core5.http.protocol.RequestTargetHost;
import org.apache.hc.core5.http2.HttpVersionPolicy;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.net.URIAuthority;
import org.apache.hc.core5.util.Args;
import org.apache.hc.core5.util.ByteArrayBuffer;
import org.apache.hc.core5.util.Timeout;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.network.ClientCertificatesOptions;
import org.zaproxy.addon.network.ConnectionOptions;
import org.zaproxy.addon.network.common.ZapSocketTimeoutException;
import org.zaproxy.addon.network.common.ZapUnknownHostException;
import org.zaproxy.addon.network.internal.client.BaseHttpSender;
import org.zaproxy.addon.network.internal.client.LegacyUtils;
import org.zaproxy.addon.network.internal.client.ResponseBodyConsumer;
import org.zaproxy.addon.network.internal.client.SocksProxy;
import org.zaproxy.addon.network.internal.client.apachev5.h2.HttpMessageRequestProducer;
import org.zaproxy.addon.network.internal.client.apachev5.h2.HttpMessageResponseConsumer;
import org.zaproxy.addon.network.internal.client.apachev5.h2.ZapClientTlsStrategy;
import org.zaproxy.addon.network.internal.server.http.handlers.LegacyProxyListenerHandler;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.users.User;

/** A {@link BaseHttpSender} using Apache HttpComponents Client. */
public class HttpSenderApache
        extends BaseHttpSender<HttpSenderContextApache, ZapHttpClientContext, HttpEntity> {

    private static final Logger LOGGER = LogManager.getLogger(HttpSenderApache.class);

    private static final int BUFFER_SIZE = 4096;

    private final Supplier<CookieStore> globalCookieStoreProvider;
    private final ConnectionOptions options;
    private final ClientCertificatesOptions clientCertificatesOptions;
    private final Supplier<LegacyProxyListenerHandler> legacyProxyListenerHandler;

    private final Lookup<AuthSchemeFactory> authSchemeRegistry;

    private final ProxyRoutePlanner routePlanner;
    private final ProxyCredentialsProvider credentialsProvider;
    private final RequestConfig defaultRequestConfig;
    private final ManagedHttpClientConnectionFactory managedHttpClientConnectionFactory;
    private final CharCodingConfig charCodingConfig;
    private final OutgoingContentStrategy outgoingContentStrategy;
    private final LayeredConnectionSocketFactory sslSocketFactory;

    private final PoolingHttpClientConnectionManager connectionManager;
    private final HttpProcessor proxyHttpProcessor;
    private final ZapRequestAddCookies zapRequestAddCookies;
    private final HttpProcessor mainHttpProcessor;
    private final RequestRetryStrategy requestRetryStrategy;
    private final CloseableHttpClient clientImpl;
    private final CloseableHttpAsyncClient h2ClientImpl;
    private final HttpConnector httpConnector;
    private ConnectionConfig connConfig;

    public HttpSenderApache(
            Supplier<CookieStore> globalCookieStoreProvider,
            ConnectionOptions options,
            ClientCertificatesOptions clientCertificatesOptions,
            Supplier<LegacyProxyListenerHandler> legacyProxyListenerHandler) {
        this.globalCookieStoreProvider = Objects.requireNonNull(globalCookieStoreProvider);
        this.options = Objects.requireNonNull(options);
        this.clientCertificatesOptions = Objects.requireNonNull(clientCertificatesOptions);
        this.legacyProxyListenerHandler = legacyProxyListenerHandler;

        authSchemeRegistry =
                RegistryBuilder.<AuthSchemeFactory>create()
                        .register(StandardAuthScheme.BASIC, BasicSchemeFactory.INSTANCE)
                        .register(StandardAuthScheme.DIGEST, DigestSchemeFactory.INSTANCE)
                        .register(StandardAuthScheme.NTLM, NTLMSchemeFactory.INSTANCE)
                        .register(StandardAuthScheme.SPNEGO, SPNegoSchemeFactory.DEFAULT)
                        .register(StandardAuthScheme.KERBEROS, KerberosSchemeFactory.DEFAULT)
                        .build();

        routePlanner = new ProxyRoutePlanner(options);
        credentialsProvider = new ProxyCredentialsProvider(options);
        defaultRequestConfig =
                RequestConfig.custom()
                        .setCookieSpec(StandardCookieSpec.IGNORE)
                        .setAuthenticationEnabled(false)
                        .build();

        outgoingContentStrategy = new OutgoingContentStrategy();

        charCodingConfig =
                CharCodingConfig.custom()
                        .setCharset(StandardCharsets.UTF_8)
                        .setMalformedInputAction(CodingErrorAction.REPLACE)
                        .setUnmappableInputAction(CodingErrorAction.REPLACE)
                        .build();

        managedHttpClientConnectionFactory =
                ManagedHttpClientConnectionFactory.builder()
                        .charCodingConfig(charCodingConfig)
                        .outgoingContentLengthStrategy(outgoingContentStrategy)
                        .responseParserFactory(new LenientMessageParserFactory())
                        .build();

        sslSocketFactory = new SslConnectionSocketFactory(options, clientCertificatesOptions);

        connectionManager =
                new ZapPoolingHttpClientConnectionManager(
                        sslSocketFactory, managedHttpClientConnectionFactory);

        proxyHttpProcessor =
                HttpProcessorBuilder.create()
                        .add(new RequestTargetHost())
                        .add(new ConnectRequestInterceptor(options))
                        .build();

        zapRequestAddCookies = new ZapRequestAddCookies();
        mainHttpProcessor =
                HttpProcessorBuilder.create()
                        .add(zapRequestAddCookies)
                        .add(new ResponseProcessCookies())
                        .add(new RemoveTransferEncoding())
                        .build();

        requestRetryStrategy = new RequestRetryStrategy();

        clientImpl =
                CustomHttpClientCreator.create(
                        connectionManager,
                        routePlanner,
                        authSchemeRegistry,
                        credentialsProvider,
                        defaultRequestConfig,
                        proxyHttpProcessor,
                        mainHttpProcessor,
                        requestRetryStrategy);

        refreshConnectionManager();
        options.addChangesListener(this::refreshConnectionManager);

        h2ClientImpl =
                CustomH2AsyncClientCreator.create(
                        charCodingConfig,
                        routePlanner,
                        authSchemeRegistry,
                        credentialsProvider,
                        defaultRequestConfig,
                        proxyHttpProcessor,
                        mainHttpProcessor,
                        requestRetryStrategy,
                        host -> connConfig,
                        new ZapClientTlsStrategy(false, options, clientCertificatesOptions));
        h2ClientImpl.start();

        httpConnector =
                new HttpConnector(
                        managedHttpClientConnectionFactory,
                        defaultRequestConfig,
                        HttpProcessorBuilder.create().build());
    }

    private void refreshConnectionManager() {
        Timeout timeout = Timeout.ofSeconds(options.getTimeoutInSecs());
        connConfig =
                ConnectionConfig.custom()
                        .setConnectTimeout(timeout)
                        .setSocketTimeout(timeout)
                        .build();
        connectionManager.setDefaultConnectionConfig(connConfig);

        connectionManager.setDefaultTlsConfig(
                TlsConfig.custom()
                        .setHandshakeTimeout(timeout)
                        .setVersionPolicy(HttpVersionPolicy.FORCE_HTTP_1)
                        .setSupportedProtocols(options.getTlsProtocols().toArray(new String[0]))
                        .build());
    }

    @Override
    public void close() {
        clientImpl.close(CloseMode.GRACEFUL);
        h2ClientImpl.close(CloseMode.GRACEFUL);
    }

    @Override
    public boolean isGlobalStateEnabled() {
        return options.isUseGlobalHttpState();
    }

    @Override
    public HttpSenderContextApache createContextImpl(HttpSender parent, int initiator) {
        return new HttpSenderContextApache(parent, initiator);
    }

    @Override
    public ZapHttpClientContext createRequestContext(
            HttpSenderContextApache ctx, HttpRequestConfig requestConfig) {
        ZapHttpClientContext context = new ZapHttpClientContext();

        if (ctx.getInitiator() != CHECK_FOR_UPDATES_INITIATOR) {
            context.setAttribute(SslConnectionSocketFactory.LAX_ATTR_NAME, Boolean.TRUE);
        }

        context.setAttribute(RequestRetryStrategy.CUSTOM_RETRY, ctx.getRequestRetryStrategy());

        if (requestConfig.getSoTimeout() != HttpRequestConfig.NO_VALUE_SET) {
            context.setRequestConfig(
                    RequestConfig.custom()
                            .setResponseTimeout(
                                    Timeout.ofMilliseconds(requestConfig.getSoTimeout()))
                            .build());
        }

        SocksProxy socksProxy = options.getSocksProxy();
        if (!options.isHttpProxyEnabled()
                && options.isSocksProxyEnabled()
                && socksProxy.getVersion() == SocksProxy.Version.SOCKS5
                && socksProxy.isUseDns()) {
            context.setAttribute(ZapHttpClientConnectionOperator.NO_RESOLVE_HOSTNAME, Boolean.TRUE);
        }

        return context;
    }

    @Override
    protected byte[] getBytes(HttpEntity body) throws IOException {
        if (body == null) {
            return null;
        }

        int entityContentLength = (int) Args.checkContentLength(body);
        int contentLength = entityContentLength < 0 ? BUFFER_SIZE : entityContentLength;
        try (InputStream is = body.getContent()) {
            if (is == null) {
                return null;
            }
            ByteArrayBuffer bb = new ByteArrayBuffer(contentLength);
            byte[] buffer = new byte[BUFFER_SIZE];
            int read;
            try {
                while ((read = is.read(buffer)) != -1) {
                    bb.append(buffer, 0, read);
                }
            } catch (ConnectionClosedException e) {
                rethrowIfNotPrematureEnd(e);
            }
            return bb.toByteArray();
        }
    }

    private static void rethrowIfNotPrematureEnd(ConnectionClosedException e) throws IOException {
        String message = e.getMessage();
        if (message == null || !message.startsWith("Premature end")) {
            throw e;
        }
    }

    @Override
    protected InputStream getStream(HttpEntity body) throws IOException {
        if (body == null) {
            return null;
        }

        return body.getContent();
    }

    @Override
    protected void sendImpl(
            HttpSenderContextApache ctx,
            ZapHttpClientContext requestContext,
            HttpRequestConfig requestConfig,
            HttpMessage message,
            ResponseBodyConsumer<HttpEntity> responseBodyConsumer)
            throws IOException {
        try {
            sendImpl0(ctx, requestContext, message, responseBodyConsumer);
        } catch (SocketTimeoutException e) {
            LOGGER.debug("A timeout occurred while sending the request:", e);
            throw new ZapSocketTimeoutException(e, options.getTimeoutInSecs());
        } catch (UnknownHostException e) {
            LOGGER.debug("An unknown host exception occurred while sending the request:", e);
            throw new ZapUnknownHostException(e, isProxyHost(e.getMessage()));
        } catch (IOException e) {
            LOGGER.debug("An I/O error occurred while sending the request:", e);
            throw e;
        } catch (Exception e) {
            LOGGER.warn("An error occurred while sending the request:", e);
            throw new IOException(e);
        }
    }

    private boolean isProxyHost(String exceptionMessage) {
        if (!options.isHttpProxyEnabled() || exceptionMessage == null) {
            return false;
        }
        // Exception message can be just the host or the host plus some other details.
        return exceptionMessage.startsWith(options.getHttpProxy().getHost());
    }

    private void sendImpl0(
            HttpSenderContextApache ctx,
            ZapHttpClientContext requestCtx,
            HttpMessage message,
            ResponseBodyConsumer<HttpEntity> responseBodyConsumer)
            throws IOException {
        message.setResponseFromTargetHost(false);

        RequestConfig.Builder requestConfigBuilder =
                RequestConfig.copy(requestCtx.getRequestConfig());

        boolean reauthenticate = false;
        requestCtx.setAttribute(ZapProtocolExec.AUTH_DISABLED_ATTR, Boolean.TRUE);
        boolean reauthenticateProxy =
                ctx.isRemoveUserDefinedAuthHeaders()
                        && credentialsProvider.hasProxyAuth()
                        && message.getRequestHeader().getHeader(HttpHeader.PROXY_AUTHORIZATION)
                                != null;
        if (reauthenticateProxy
                || (!ctx.isRemoveUserDefinedAuthHeaders()
                        && message.getRequestHeader().getHeader(HttpHeader.PROXY_AUTHORIZATION)
                                != null)) {
            requestCtx.setAttribute(ZapProtocolExec.PROXY_AUTH_DISABLED_ATTR, Boolean.TRUE);
        }
        User user = ctx.getUser(message);
        if (user != null) {
            requestConfigBuilder.setCookieSpec(StandardCookieSpec.RELAXED);
            requestCtx.setCookieStore(
                    LegacyUtils.httpStateToCookieStore(user.getCorrespondingHttpState()));

            boolean authHeaderPresent =
                    message.getRequestHeader().getHeader(HttpHeader.AUTHORIZATION) != null;
            reauthenticate = ctx.isRemoveUserDefinedAuthHeaders() && authHeaderPresent;
            if (!authHeaderPresent) {
                requestCtx.setCredentialsProvider(
                        new HttpStateCredentialsProvider(user.getCorrespondingHttpState()));
                requestCtx.setAttribute(ZapProtocolExec.AUTH_DISABLED_ATTR, Boolean.FALSE);
            }
        } else {
            switch (ctx.getCookieUsage()) {
                case GLOBAL:
                    if (isGlobalStateEnabled()) {
                        requestConfigBuilder.setCookieSpec(StandardCookieSpec.RELAXED);
                        requestCtx.setCookieStore(globalCookieStoreProvider.get());
                    } else {
                        requestConfigBuilder.setCookieSpec(StandardCookieSpec.IGNORE);
                    }
                    break;
                case LOCAL:
                    requestConfigBuilder.setCookieSpec(StandardCookieSpec.RELAXED);
                    requestCtx.setCookieStore(ctx.getLocalCookieStore());
                    break;
                case IGNORE:
                default:
                    requestConfigBuilder.setCookieSpec(StandardCookieSpec.IGNORE);
                    break;
            }
            requestCtx.setCredentialsProvider(credentialsProvider);
        }
        requestCtx.setRequestConfig(requestConfigBuilder.build());

        Map<String, Object> properties = getProperties(message);
        HttpRequest request = createHttpRequest(properties, message);

        requestCtx.increaseRequestCount();
        try {
            if (HttpRequestHeader.CONNECT.equals(message.getRequestHeader().getMethod())) {
                String host = message.getRequestHeader().getHostName();
                int port = message.getRequestHeader().getHostPort();
                Object hostValue = properties.get("target.host");
                if (hostValue != null) {
                    host = hostValue.toString();
                }
                Object portValue = properties.get("target.port");
                if (portValue != null) {
                    try {
                        port = Integer.parseInt(portValue.toString());
                    } catch (NumberFormatException ignore) {
                    }
                }

                message.setTimeSentMillis(System.currentTimeMillis());
                httpConnector.connect(
                        (ClassicHttpRequest) request,
                        requestCtx,
                        new HttpHost(host, port),
                        (response, socket) -> {
                            copyResponse(response, message, responseBodyConsumer);
                            message.setUserObject(socket);
                        });
            } else {
                for (; ; ) {
                    message.setTimeSentMillis(System.currentTimeMillis());
                    if (isHttp2(properties, message)) {
                        sendHttp2(message, request, requestCtx);
                    } else {
                        try {
                            clientImpl.execute(
                                    (ClassicHttpRequest) request,
                                    requestCtx,
                                    response -> {
                                        copyResponse(response, message, responseBodyConsumer);
                                        return null;
                                    });
                        } catch (ConnectionClosedException e) {
                            rethrowIfNotPrematureEnd(e);
                            break;
                        }
                    }

                    if (reauthenticateProxy && isProxyAuthNeeded(request, message)) {
                        reauthenticateProxy = false;
                        requestCtx.setAttribute(
                                ZapProtocolExec.PROXY_AUTH_DISABLED_ATTR, Boolean.FALSE);
                        continue;
                    }

                    if (!reauthenticate || !isAuthNeeded(requestCtx, user, request, message)) {
                        break;
                    }
                    reauthenticate = false;
                }
            }
        } finally {
            message.setTimeElapsedMillis(
                    (int) (System.currentTimeMillis() - message.getTimeSentMillis()));
        }

        if (!isSet(requestCtx, "zap.initial-cookie-setup")) {
            requestCtx.setAttribute(
                    "zap.initial-cookie-origin",
                    requestCtx.getAttribute(HttpClientContext.COOKIE_ORIGIN));
            requestCtx.setAttribute(
                    "zap.initial-cookie-spec",
                    requestCtx.getAttribute(HttpClientContext.COOKIE_SPEC));
        }

        updateRequestHeaders(message.getRequestHeader(), requestCtx.getRequest());

        if (isSet(requestCtx, RemoveTransferEncoding.ATTR_NAME) && !message.isEventStream()) {
            message.getResponseHeader().setContentLength(message.getResponseBody().length());
        }

        if (user != null) {
            LegacyUtils.updateHttpState(
                    user.getCorrespondingHttpState(), requestCtx.getCookieStore());
        }

        HttpClientConnection connection =
                (HttpClientConnection) requestCtx.getAttribute(ZapHttpRequestExecutor.CONNECTION);
        if (connection == null) {
            return;
        }

        if (!connection.isOpen()) {
            message.setUserObject(Collections.singletonMap("connection.closed", Boolean.TRUE));
            return;
        }

        Socket socket = (Socket) requestCtx.getAttribute(ZapHttpRequestExecutor.CONNECTION_SOCKET);
        processSocket(properties, requestCtx, message, socket);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> getProperties(HttpMessage message) {
        Object userObject = message.getUserObject();
        if (!(userObject instanceof Map)) {
            userObject = new HashMap<>();
        }
        return (Map<String, Object>) userObject;
    }

    private static boolean isHttp2(Map<String, Object> properties, HttpMessage message) {
        if (Boolean.TRUE.equals(properties.get("zap.h2"))) {
            return true;
        }
        return "HTTP/2".equalsIgnoreCase(message.getRequestHeader().getVersion());
    }

    private void sendHttp2(
            HttpMessage message, HttpRequest request, ZapHttpClientContext requestCtx)
            throws IOException {

        CloseableHttpAsyncClient client;
        boolean lax =
                Boolean.TRUE.equals(
                        requestCtx.getAttribute(SslConnectionSocketFactory.LAX_ATTR_NAME));
        if (lax) {
            client = h2ClientImpl;
        } else {
            client =
                    CustomH2AsyncClientCreator.create(
                            charCodingConfig,
                            routePlanner,
                            authSchemeRegistry,
                            credentialsProvider,
                            defaultRequestConfig,
                            proxyHttpProcessor,
                            mainHttpProcessor,
                            requestRetryStrategy,
                            host -> connConfig,
                            new ZapClientTlsStrategy(false, options, clientCertificatesOptions));
            client.start();
        }

        try {
            client.execute(
                            new HttpMessageRequestProducer(request, message.getRequestBody()),
                            new HttpMessageResponseConsumer(message),
                            requestCtx,
                            new FutureCallback<HttpMessage>() {

                                @Override
                                public void completed(HttpMessage response) {
                                    // Nothing to do.
                                }

                                @Override
                                public void failed(Exception ex) {
                                    // Nothing to do.
                                }

                                @Override
                                public void cancelled() {
                                    // Nothing to do.
                                }
                            })
                    .get();
            message.setResponseFromTargetHost(true);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException(e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException) {
                throw (IOException) cause;
            }
            throw new IOException(cause);
        } catch (Exception e) {
            throw new IOException(e);
        } finally {
            if (!lax) {
                client.close(CloseMode.GRACEFUL);
            }
        }
    }

    private static boolean isAuthNeeded(
            ZapHttpClientContext requestCtx, User user, HttpRequest request, HttpMessage message) {
        int statusCode = message.getResponseHeader().getStatusCode();
        if (statusCode != HttpStatusCode.UNAUTHORIZED && statusCode != HttpStatusCode.FORBIDDEN) {
            return false;
        }

        request.removeHeaders(HttpHeader.AUTHORIZATION);
        requestCtx.setCredentialsProvider(
                new HttpStateCredentialsProvider(user.getCorrespondingHttpState()));
        requestCtx.setAttribute(ZapProtocolExec.AUTH_DISABLED_ATTR, Boolean.FALSE);
        return true;
    }

    private static boolean isProxyAuthNeeded(HttpRequest request, HttpMessage message) {
        int statusCode = message.getResponseHeader().getStatusCode();
        if (statusCode != HttpStatusCode.PROXY_AUTHENTICATION_REQUIRED
                && statusCode != HttpStatusCode.FORBIDDEN) {
            return false;
        }

        request.removeHeaders(HttpHeader.PROXY_AUTHORIZATION);
        return true;
    }

    @SuppressWarnings("deprecation")
    private void processSocket(
            Map<String, Object> properties,
            ZapHttpClientContext requestCtx,
            HttpMessage message,
            Socket socket)
            throws IOException {
        if (socket == null) {
            return;
        }

        InputStream inputStream =
                (InputStream)
                        requestCtx.getAttribute(ZapHttpRequestExecutor.CONNECTION_INPUT_STREAM);
        org.zaproxy.zap.ZapGetMethod method =
                new org.zaproxy.zap.ZapGetMethod() {
                    @Override
                    public InputStream getResponseBodyAsStream() {
                        return inputStream;
                    }
                };
        method.setUpgradedSocket(socket);
        method.setUpgradedInputStream(socket.getInputStream());
        message.setUserObject(method);

        if (isPersistentManualConnection(properties)
                && !legacyProxyListenerHandler
                        .get()
                        .notifyPersistentConnectionListener(message, null, method)) {
            closeSilently(socket);
        }
    }

    private static boolean isPersistentManualConnection(Map<String, Object> properties) {
        Object persistent = properties.get("connection.manual.persistent");
        if (persistent == Boolean.TRUE) {
            return true;
        }
        return false;
    }

    private static void closeSilently(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignore) {
            // Nothing to do.
        }
    }

    private static void copyResponse(
            HttpResponse response,
            HttpMessage message,
            ResponseBodyConsumer<HttpEntity> responseBodyConsumer)
            throws IOException {
        message.setResponseFromTargetHost(true);

        HttpResponseHeader responseHeader = message.getResponseHeader();
        try {
            responseHeader.setMessage(
                    response + " " + response.getCode() + getReasonPhrase(response));
        } catch (HttpMalformedHeaderException e) {
            throw new IOException(e);
        }
        copyHeaders(response, responseHeader);

        HttpEntity entity = null;
        if (response instanceof ClassicHttpResponse) {
            entity = ((ClassicHttpResponse) response).getEntity();
        }
        responseBodyConsumer.accept(message, entity);
    }

    private static boolean isSet(HttpContext context, String attributeName) {
        return context.getAttribute(attributeName) != null;
    }

    @Override
    protected void updateInitialMessage(
            HttpSenderContextApache ctx, ZapHttpClientContext requestCtx, HttpMessage message) {

        if (requestCtx.getRequestCount() != 1 && requestCtx.hasCookieSetup()) {
            try {
                zapRequestAddCookies.process(
                        requestCtx.getFirstRequest(), null, requestCtx.getCookieContext());
            } catch (Exception e) {
                LOGGER.error("An error occurred while updating the request cookies:", e);
            }
        }
    }

    private static void updateRequestHeaders(HttpRequestHeader req, HttpRequest httpRequest) {
        try {
            req.setMessage(req.getPrimeHeader());
            copyHeaders(httpRequest, req);
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error("An error occurred while updating the request headers:", e);
        }
    }

    private static HttpRequest createHttpRequest(Map<String, Object> properties, HttpMessage msg) {
        if (isHttp2(properties, msg)) {
            HttpRequestHeader requestHeader = msg.getRequestHeader();

            String path = requestHeader.getURI().getEscapedPathQuery();
            URI uri = requestHeader.getURI();
            HttpRequest request =
                    new BasicHttpRequest(
                            requestHeader.getMethod(),
                            uri.getScheme() == null ? HttpHeader.HTTPS : uri.getScheme(),
                            new URIAuthority(new String(uri.getRawHost()), uri.getPort()),
                            path == null ? "/" : path);

            for (HttpHeaderField header : requestHeader.getHeaders()) {
                String name = header.getName();
                String value = header.getValue();
                request.addHeader(name, value);
            }

            return request;
        }

        boolean hostNormalisation = !Boolean.FALSE.equals(properties.get("host.normalization"));
        if (hostNormalisation) {
            String host = null;
            Object hostValue = properties.get("host");
            if (hostValue != null) {
                host = hostValue.toString();
            }

            addHostHeader(msg, host);
        }

        BasicClassicHttpRequest copy =
                new BasicClassicHttpRequest(
                        msg.getRequestHeader().getMethod(),
                        getScheme(
                                msg.getRequestHeader().getMethod(),
                                msg.getRequestHeader().getURI()),
                        new URIAuthority(
                                msg.getRequestHeader().getURI().getEscapedUserinfo(),
                                msg.getRequestHeader().getHostName(),
                                msg.getRequestHeader().getHostPort()),
                        getPath(msg));
        copy.setVersion(toHttpVersion(msg.getRequestHeader().getVersion()));
        boolean skipHostHeader = false;
        for (HttpHeaderField header : msg.getRequestHeader().getHeaders()) {
            if (hostNormalisation && HttpRequestHeader.HOST.equals(header.getName())) {
                if (skipHostHeader) {
                    continue;
                }
                skipHostHeader = true;
            }
            copy.addHeader(header.getName(), header.getValue());
        }

        copy.setEntity(new ByteArrayEntity(msg.getRequestBody().getBytes(), null));

        return copy;
    }

    private static String getPath(HttpMessage msg) {
        if (HttpRequestHeader.CONNECT.equals(msg.getRequestHeader().getMethod())) {
            return msg.getRequestHeader().getURI().toString();
        }
        String path = msg.getRequestHeader().getURI().getEscapedPathQuery();
        if (path == null) {
            return "/";
        }
        return path;
    }

    private static String getScheme(String method, URI uri) {
        String scheme = uri.getScheme();
        if (scheme != null) {
            return scheme;
        }
        return "http";
    }

    private static ProtocolVersion toHttpVersion(String version) {
        String[] data = version.substring(version.indexOf('/') + 1).split("\\.", 2);
        int major = Integer.parseInt(data[0]);
        int minor = data.length > 1 ? Integer.parseInt(data[1]) : 0;
        return new HttpVersion(major, minor);
    }

    private static void addHostHeader(HttpMessage msg, String host) {
        HttpRequestHeader header = msg.getRequestHeader();
        String expectedHost = host != null ? host : createExpectedHost(header);
        String currentHost = header.getHeader(HttpRequestHeader.HOST);
        if (currentHost == null) {
            header.addHeader(HttpRequestHeader.HOST, expectedHost);
            return;
        }
        header.setHeader(HttpRequestHeader.HOST, expectedHost);
    }

    private static String createExpectedHost(HttpRequestHeader header) {
        char[] rawHost = header.getURI().getRawHost();
        if (rawHost == null) {
            return header.getURI().getEscapedAuthority();
        }
        StringBuilder host = new StringBuilder();
        host.append(rawHost);
        int port = header.getURI().getPort();
        boolean appendPort = false;
        if (port != -1) {
            if (header.isSecure()) {
                appendPort = port != 443;
            } else {
                appendPort = port != 80;
            }

            if (appendPort) {
                host.append(':').append(port);
            }
        }
        return host.toString();
    }

    private static String getReasonPhrase(HttpResponse response) {
        String reason = response.getReasonPhrase();
        return reason != null ? " " + reason : "";
    }

    private static void copyHeaders(MessageHeaders from, HttpHeader to) {
        for (Iterator<Header> it = from.headerIterator(); it.hasNext(); ) {
            Header header = it.next();
            String name = header.getName();
            if (HttpHeader.CONTENT_LENGTH.equalsIgnoreCase(name)) {
                String contentLength = header.getValue();
                try {
                    to.setContentLength(Integer.parseInt(contentLength));
                } catch (NumberFormatException e) {
                    LOGGER.debug("Invalid content-length value: {}", contentLength);
                }
                // Set it again to keep the exact case.
                to.setHeader(name, contentLength);
            } else {
                to.addHeader(name, header.getValue());
            }
        }
    }
}
