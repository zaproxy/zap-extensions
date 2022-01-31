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
package org.zaproxy.addon.network.internal.server.http;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.util.concurrent.EventExecutorGroup;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.security.SslCertificateService;

/** Unit test for {@link HttpServer}. */
class HttpServerUnitTest {

    private NioEventLoopGroup group;
    private EventExecutorGroup mainHandlerExecutor;
    private SslCertificateService sslCertificateService;
    private Supplier<MainServerHandler> handlerSupplier;

    @BeforeEach
    void setUp() throws Exception {
        group = mock(NioEventLoopGroup.class);
        mainHandlerExecutor = mock(EventExecutorGroup.class);
        sslCertificateService = mock(SslCertificateService.class);
        handlerSupplier = () -> mock(MainServerHandler.class);
    }

    @Test
    void shouldThrowIfNoEventLoopGroup() throws Exception {
        // Given
        group = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () ->
                        new HttpServer(
                                group,
                                mainHandlerExecutor,
                                sslCertificateService,
                                handlerSupplier));
    }

    @Test
    void shouldThrowIfNoEventExecutorGroup() throws Exception {
        // Given
        mainHandlerExecutor = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () ->
                        new HttpServer(
                                group,
                                mainHandlerExecutor,
                                sslCertificateService,
                                handlerSupplier));
    }

    @Test
    void shouldThrowIfNoSslCertificateService() throws Exception {
        // Given
        sslCertificateService = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () ->
                        new HttpServer(
                                group,
                                mainHandlerExecutor,
                                sslCertificateService,
                                handlerSupplier));
    }

    @Test
    void shouldThrowIfNoMainHandlerSupplier() throws Exception {
        // Given
        handlerSupplier = null;
        // When / Then
        assertThrows(
                NullPointerException.class,
                () ->
                        new HttpServer(
                                group,
                                mainHandlerExecutor,
                                sslCertificateService,
                                handlerSupplier));
    }

    @Test
    void shouldCreate() throws Exception {
        assertDoesNotThrow(
                () ->
                        new HttpServer(
                                group,
                                mainHandlerExecutor,
                                sslCertificateService,
                                handlerSupplier));
    }
}
