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
package org.zaproxy.addon.network.server;

import java.util.Objects;
import javax.net.ssl.X509TrustManager;
import org.parosproxy.paros.network.HttpSender;

/**
 * The configuration for an HTTP server.
 *
 * @since 0.11.0
 * @see #builder()
 */
public class HttpServerConfig {

    private final HttpMessageHandler httpMessageHandler;
    private final HttpSender httpSender;
    private final boolean serveZapApi;
    private final X509TrustManager trustManager;

    private HttpServerConfig(
            HttpMessageHandler httpMessageHandler,
            HttpSender httpSender,
            boolean serveZapApi,
            X509TrustManager trustManager) {
        this.httpMessageHandler = httpMessageHandler;
        this.httpSender = httpSender;
        this.serveZapApi = serveZapApi;
        this.trustManager = trustManager;
    }

    public HttpMessageHandler getHttpMessageHandler() {
        return httpMessageHandler;
    }

    public HttpSender getHttpSender() {
        return httpSender;
    }

    public boolean isServeZapApi() {
        return serveZapApi;
    }

    /**
     * Gets the trust manager to use to validate client certificates, or {@code null} if client
     * certificate authentication is not required.
     *
     * @return the trust manager, or {@code null}.
     * @since 0.29.0
     */
    public X509TrustManager getTrustManager() {
        return trustManager;
    }

    /**
     * Creates a builder of {@link HttpServerConfig}.
     *
     * @return a new builder.
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * A builder of {@link HttpServerConfig}.
     *
     * @see #build()
     */
    public static class Builder {

        private HttpMessageHandler httpMessageHandler;

        private HttpSender httpSender;

        private boolean serveZapApi;

        private X509TrustManager trustManager;

        /**
         * Sets the HTTP message handler.
         *
         * @param httpMessageHandler the HTTP message handler, must not be {@code null}.
         * @throws NullPointerException if the given {@code httpMessageHandler} is {@code null}.
         * @return the builder for chaining.
         */
        public Builder setHttpMessageHandler(HttpMessageHandler httpMessageHandler) {
            this.httpMessageHandler = Objects.requireNonNull(httpMessageHandler);
            return this;
        }

        /**
         * Sets the HTTP sender, which will make the server act as a proxy.
         *
         * @param httpSender the HTTP sender.
         * @return the builder for chaining.
         */
        public Builder setHttpSender(HttpSender httpSender) {
            this.httpSender = httpSender;
            return this;
        }

        /**
         * Sets whether or not the API should be served.
         *
         * @param serveZapApi {@code true} if the API should be served, {@code false} otherwise.
         * @return the builder for chaining.
         */
        public Builder setServeZapApi(boolean serveZapApi) {
            this.serveZapApi = serveZapApi;
            return this;
        }

        /**
         * Sets the trust manager used to validate client certificates, making client certificate
         * authentication required. Pass {@code null} to disable client certificate authentication.
         *
         * @param trustManager the trust manager, or {@code null} to disable client certificate
         *     authentication.
         * @return the builder for chaining.
         * @since 0.29.0
         */
        public Builder setTrustManager(X509TrustManager trustManager) {
            this.trustManager = trustManager;
            return this;
        }

        /**
         * Builds the {@link HttpServerConfig} with properties set.
         *
         * @return the configuration.
         * @throws IllegalStateException if any of the required properties were not set.
         */
        public HttpServerConfig build() {
            if (httpMessageHandler == null) {
                throw new IllegalStateException("The httpMessageHandler was not set.");
            }

            return new HttpServerConfig(httpMessageHandler, httpSender, serveZapApi, trustManager);
        }
    }
}
