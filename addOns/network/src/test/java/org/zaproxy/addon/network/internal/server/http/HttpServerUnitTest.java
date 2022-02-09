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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.util.concurrent.DefaultEventExecutorGroup;
import io.netty.util.concurrent.DefaultThreadFactory;
import io.netty.util.concurrent.EventExecutorGroup;
import java.io.IOException;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.security.SslCertificateService;
import org.zaproxy.addon.network.server.Server;

/** Unit test for {@link HttpServer}. */
class HttpServerUnitTest {

    private static NioEventLoopGroup group;
    private static EventExecutorGroup mainHandlerExecutor;
    private SslCertificateService sslCertificateService;
    private Supplier<MainServerHandler> handlerSupplier;

    @BeforeAll
    static void setupAll() throws Exception {
        group = new NioEventLoopGroup(1, new DefaultThreadFactory("ZAP-HttpServerUnitTest"));
        mainHandlerExecutor =
                new DefaultEventExecutorGroup(
                        1, new DefaultThreadFactory("ZAP-HttpServerUnitTest-Events"));
    }

    @AfterAll
    static void tearDownAll() throws Exception {
        if (group != null) {
            group.shutdownGracefully();
            group = null;
        }

        if (mainHandlerExecutor != null) {
            mainHandlerExecutor.shutdownGracefully();
            mainHandlerExecutor = null;
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        sslCertificateService = mock(SslCertificateService.class);
        handlerSupplier = () -> mock(MainServerHandler.class);
    }

    @Test
    void shouldThrowIfNoEventLoopGroup() throws Exception {
        // Given
        NioEventLoopGroup group = null;
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
        EventExecutorGroup mainHandlerExecutor = null;
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

    @Test
    void shouldCreateWithNoHandler() throws Exception {
        assertDoesNotThrow(() -> new HttpServer(group, mainHandlerExecutor, sslCertificateService));
    }

    @Test
    void shouldFailToStartWithNoHandler() throws Exception {
        try (HttpServer server =
                new HttpServer(group, mainHandlerExecutor, sslCertificateService)) {
            IOException exception =
                    assertThrows(IOException.class, () -> server.start(Server.ANY_PORT));
            assertThat(exception.getMessage(), is(equalTo("No main server handler set.")));
        }
    }

    @Test
    void shouldStartWithHandlerSet() throws Exception {
        try (HttpServer server =
                new HttpServer(group, mainHandlerExecutor, sslCertificateService)) {
            server.setMainServerHandler(handlerSupplier);
            assertDoesNotThrow(() -> server.start(Server.ANY_PORT));
        }
    }

    @Test
    void shouldThrowIfSettingNullHandler() throws Exception {
        // Given
        handlerSupplier = null;
        // When / Then
        try (HttpServer server =
                new HttpServer(group, mainHandlerExecutor, sslCertificateService)) {
            assertThrows(
                    NullPointerException.class, () -> server.setMainServerHandler(handlerSupplier));
        }
    }
}
