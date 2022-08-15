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
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;
import org.apache.commons.httpclient.URI;
import org.apache.hc.client5.http.auth.AuthSchemeFactory;
import org.apache.hc.client5.http.auth.StandardAuthScheme;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.config.TlsConfig;
import org.apache.hc.client5.http.cookie.CookieStore;
import org.apache.hc.client5.http.cookie.StandardCookieSpec;
import org.apache.hc.client5.http.impl.auth.BasicSchemeFactory;
import org.apache.hc.client5.http.impl.auth.DigestSchemeFactory;
import org.apache.hc.client5.http.impl.auth.KerberosSchemeFactory;
import org.apache.hc.client5.http.impl.auth.NTLMSchemeFactory;
import org.apache.hc.client5.http.impl.auth.SPNegoSchemeFactory;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CustomHttpClientCreator;
import org.apache.hc.client5.http.impl.classic.ZapRequestAddCookies;
import org.apache.hc.client5.http.impl.io.ManagedHttpClientConnectionFactory;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.ZapHttpClientConnectionOperator;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.client5.http.protocol.ResponseProcessCookies;
import org.apache.hc.client5.http.socket.LayeredConnectionSocketFactory;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
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
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.BasicClassicHttpRequest;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.http.protocol.HttpProcessor;
import org.apache.hc.core5.http.protocol.HttpProcessorBuilder;
import org.apache.hc.core5.http.protocol.RequestTargetHost;
import org.apache.hc.core5.http2.HttpVersionPolicy;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.net.URIAuthority;
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
import org.zaproxy.addon.network.ClientCertificatesOptions;
import org.zaproxy.addon.network.ConnectionOptions;
import org.zaproxy.addon.network.internal.client.BaseHttpSender;
import org.zaproxy.addon.network.internal.client.LegacyUtils;
import org.zaproxy.addon.network.internal.client.ResponseBodyConsumer;
import org.zaproxy.addon.network.internal.client.SocksProxy;
import org.zaproxy.zap.ZapGetMethod;
import org.zaproxy.zap.network.HttpRequestConfig;
import org.zaproxy.zap.users.User;

/** A {@link BaseHttpSender} using Apache HttpComponents Client. */
public class HttpSenderApache
        extends BaseHttpSender<HttpSenderContextApache, ZapHttpClientContext, HttpEntity> {

    private static final Logger LOGGER = LogManager.getLogger(HttpSenderApache.class);

    private final Supplier<CookieStore> globalCookieStoreProvider;
    private final ConnectionOptions options;

    private final Lookup<AuthSchemeFactory> authSchemeRegistry;

    private final ProxyRoutePlanner routePlanner;
    private final ProxyCredentialsProvider credentialsProvider;
    private final RequestConfig defaultRequestConfig;
    private final ManagedHttpClientConnectionFactory managedHttpClientConnectionFactory;
    private final OutgoingContentStrategy outgoingContentStrategy;
    private final LayeredConnectionSocketFactory sslSocketFactory;

    private final PoolingHttpClientConnectionManager connectionManager;
    private final HttpProcessor proxyHttpProcessor;
    private final ZapRequestAddCookies zapRequestAddCookies;
    private final HttpProcessor mainHttpProcessor;
    private final RequestRetryStrategy requestRetryStrategy;
    private final CloseableHttpClient clientImpl;
    private final HttpConnector httpConnector;

    public HttpSenderApache(
            Supplier<CookieStore> globalCookieStoreProvider,
            ConnectionOptions options,
            ClientCertificatesOptions clientCertificatesOptions) {
        this.globalCookieStoreProvider = Objects.requireNonNull(globalCookieStoreProvider);
        this.options = Objects.requireNonNull(options);

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

        managedHttpClientConnectionFactory =
                ManagedHttpClientConnectionFactory.builder()
                        .charCodingConfig(
                                CharCodingConfig.custom()
                                        .setCharset(StandardCharsets.UTF_8)
                                        .setMalformedInputAction(CodingErrorAction.REPLACE)
                                        .setUnmappableInputAction(CodingErrorAction.REPLACE)
                                        .build())
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
                        .add(new RemoveAuthHeader(options))
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

        httpConnector =
                new HttpConnector(
                        managedHttpClientConnectionFactory,
                        defaultRequestConfig,
                        HttpProcessorBuilder.create().build());
    }

    private void refreshConnectionManager() {
        Timeout timeout = Timeout.ofSeconds(options.getTimeoutInSecs());
        connectionManager.setDefaultConnectionConfig(
                ConnectionConfig.custom()
                        .setConnectTimeout(timeout)
                        .setSocketTimeout(timeout)
                        .build());

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
    }

    @Override
    public boolean isGlobalStateEnabled() {
        return options.isUseGlobalHttpState();
    }

    @Override
    public HttpSenderContextApache createContext(HttpSender parent, int initiator) {
        return new HttpSenderContextApache(parent, initiator);
    }

    @Override
    public ZapHttpClientContext createRequestContext(
            HttpSenderContextApache ctx, HttpRequestConfig requestConfig) {
        ZapHttpClientContext context = new ZapHttpClientContext();

        if (ctx.getInitiator() != HttpSender.CHECK_FOR_UPDATES_INITIATOR) {
            context.setAttribute(SslConnectionSocketFactory.LAX_ATTR_NAME, Boolean.TRUE);
        }

        if (ctx.isRemoveUserDefinedAuthHeaders()) {
            context.setAttribute(RemoveAuthHeader.ATTR_NAME, Boolean.TRUE);
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
        return EntityUtils.toByteArray(body);
    }

    @Override
    protected InputStream getStream(HttpEntity body) throws IOException {
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
        } catch (IOException e) {
            LOGGER.debug("An I/O error occurred while sending the request:", e);
            throw e;
        } catch (Exception e) {
            LOGGER.warn("An error occurred while sending the request:", e);
            throw new IOException(e);
        }
    }

    private void sendImpl0(
            HttpSenderContextApache ctx,
            ZapHttpClientContext requestCtx,
            HttpMessage message,
            ResponseBodyConsumer<HttpEntity> responseBodyConsumer)
            throws IOException {

        RequestConfig.Builder requestConfigBuilder =
                RequestConfig.copy(requestCtx.getRequestConfig());

        User user = ctx.getUser(message);
        if (user != null) {
            requestConfigBuilder.setCookieSpec(StandardCookieSpec.RELAXED);
            requestCtx.setCookieStore(
                    LegacyUtils.httpStateToCookieStore(user.getCorrespondingHttpState()));
            requestCtx.setCredentialsProvider(
                    new HttpStateCredentialsProvider(user.getCorrespondingHttpState()));
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

        ClassicHttpRequest request = createHttpRequest(message);

        requestCtx.increaseRequestCount();
        message.setTimeSentMillis(System.currentTimeMillis());
        try {
            if (HttpRequestHeader.CONNECT.equals(message.getRequestHeader().getMethod())) {
                String host = message.getRequestHeader().getHostName();
                int port = message.getRequestHeader().getHostPort();
                Object userObject = message.getUserObject();
                if (userObject instanceof Map) {
                    Map<?, ?> metadata = (Map<?, ?>) userObject;
                    Object hostValue = metadata.get("target.host");
                    if (hostValue != null) {
                        host = hostValue.toString();
                    }
                    Object portValue = metadata.get("target.port");
                    if (portValue != null) {
                        try {
                            port = Integer.parseInt(portValue.toString());
                        } catch (NumberFormatException ignore) {
                        }
                    }
                }

                httpConnector.connect(
                        request,
                        requestCtx,
                        new HttpHost(host, port),
                        (response, socket) -> {
                            copyResponse(response, message, responseBodyConsumer);
                            message.setUserObject(socket);
                        });
            } else {
                clientImpl.execute(
                        request,
                        requestCtx,
                        response -> {
                            copyResponse(response, message, responseBodyConsumer);
                            return null;
                        });
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

        if (isSet(requestCtx, RemoveTransferEncoding.ATTR_NAME)) {
            message.getResponseHeader().setContentLength(message.getResponseBody().length());
        }

        if (user != null) {
            LegacyUtils.updateHttpState(
                    user.getCorrespondingHttpState(), requestCtx.getCookieStore());
        }

        Socket socket = (Socket) requestCtx.getAttribute(ZapHttpRequestExecutor.CONNECTION_SOCKET);
        if (socket != null) {
            InputStream inputStream =
                    (InputStream)
                            requestCtx.getAttribute(ZapHttpRequestExecutor.CONNECTION_INPUT_STREAM);
            ZapGetMethod method =
                    new ZapGetMethod() {
                        @Override
                        public InputStream getResponseBodyAsStream() {
                            return inputStream;
                        }
                    };
            method.setUpgradedSocket(socket);
            method.setUpgradedInputStream(socket.getInputStream());
            message.setUserObject(method);
        }
    }

    private static void copyResponse(
            ClassicHttpResponse response,
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
        HttpEntity entity = response.getEntity();
        if (entity != null) {
            responseBodyConsumer.accept(message, entity);
        }
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

    private static ClassicHttpRequest createHttpRequest(HttpMessage msg) {
        String host = null;
        Object userObject = msg.getUserObject();
        if (userObject instanceof Map) {
            Map<?, ?> metadata = (Map<?, ?>) userObject;
            Object hostValue = metadata.get("host");
            if (hostValue != null) {
                host = hostValue.toString();
            }
        }

        addHostHeader(msg, host);

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
            if (HttpRequestHeader.HOST.equals(header.getName())) {
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
        int minor = Integer.parseInt(data[1]);
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
            to.addHeader(header.getName(), header.getValue());
        }

        String contentLength = to.getHeader(HttpHeader.CONTENT_LENGTH);
        if (contentLength != null) {
            try {
                to.setContentLength(Integer.parseInt(contentLength));
            } catch (NumberFormatException e) {
                LOGGER.debug("Invalid content-length value: {}", contentLength);
            }
        }
    }
}
