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
import java.net.Socket;
import org.apache.hc.client5.http.HttpRoute;
import org.apache.hc.client5.http.RouteInfo.LayerType;
import org.apache.hc.client5.http.RouteInfo.TunnelType;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.io.ManagedHttpClientConnection;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.impl.io.HttpRequestExecutor;
import org.apache.hc.core5.http.io.HttpConnectionFactory;
import org.apache.hc.core5.http.protocol.HttpCoreContext;
import org.apache.hc.core5.http.protocol.HttpProcessor;

/** A HTTP connector, sends CONNECT request to a target and returns the connected socket. */
public class HttpConnector {

    private final HttpConnectionFactory<ManagedHttpClientConnection> connectionFactory;
    private final RequestConfig requestConfig;
    private final HttpProcessor httpProcessor;
    private final HttpRequestExecutor requestExecutor;

    public HttpConnector(
            HttpConnectionFactory<ManagedHttpClientConnection> connectionFactory,
            RequestConfig requestConfig,
            HttpProcessor httpProcessor) {
        super();
        this.connectionFactory = connectionFactory;
        this.requestConfig = requestConfig;
        this.httpProcessor = httpProcessor;
        this.requestExecutor = new HttpRequestExecutor();
    }

    public void connect(
            ClassicHttpRequest request,
            HttpClientContext context,
            HttpHost target,
            ConnectResponseHandler responseHandler)
            throws IOException {
        HttpRoute route =
                new HttpRoute(target, null, target, false, TunnelType.TUNNELLED, LayerType.PLAIN);

        context.setAttribute(HttpCoreContext.HTTP_REQUEST, request);
        context.setAttribute(HttpClientContext.HTTP_ROUTE, route);
        context.setAttribute(HttpClientContext.REQUEST_CONFIG, requestConfig);

        try {
            ManagedHttpClientConnection connection = connectionFactory.createConnection(null);

            requestExecutor.preProcess(request, httpProcessor, context);
            Socket socket = new Socket(target.getHostName(), target.getPort());
            connection.bind(socket);
            ClassicHttpResponse response = requestExecutor.execute(request, connection, context);
            responseHandler.handleResponse(response, socket);
        } catch (HttpException e) {
            throw new IOException(e);
        }
    }

    public interface ConnectResponseHandler {

        void handleResponse(ClassicHttpResponse response, Socket socket) throws IOException;
    }
}
