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
package org.zaproxy.addon.network.internal.handlers;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.timeout.ReadTimeoutException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLHandshakeException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.security.MissingRootCertificateException;
import org.zaproxy.addon.network.TestLogAppender;
import org.zaproxy.addon.network.internal.cert.GenerationException;

/** Unit test for {@link ServerExceptionHandler}. */
class ServerExceptionHandlerUnitTest {

    private ChannelHandlerContext ctx;
    private List<String> logEvents;
    private ServerExceptionHandler serverExceptionHandler = ServerExceptionHandler.getInstance();

    @BeforeEach
    void setUp() throws Exception {
        ctx = mock(ChannelHandlerContext.class);
        logEvents = registerLogEvents();
    }

    @AfterEach
    void cleanUp() throws Exception {
        Configurator.reconfigure(getClass().getResource("/log4j2-test.properties").toURI());
    }

    @Test
    void shouldBeSharable() {
        assertThat(serverExceptionHandler.isSharable(), is(equalTo(true)));
    }

    @Test
    void shouldCloseChannelOnCaughtException() throws Exception {
        // Given
        Exception exception = new Exception();
        // When
        serverExceptionHandler.exceptionCaught(ctx, exception);
        // Then
        verify(ctx).close();
    }

    @Test
    void shouldLogReadTimeoutAsDebug() throws Exception {
        // Given
        Exception exception = ReadTimeoutException.INSTANCE;
        // When
        serverExceptionHandler.exceptionCaught(ctx, exception);
        // Then
        assertThat(logEvents, hasItem(startsWith("DEBUG Timed out while reading")));
    }

    @Test
    void shouldLogSslHandshakeExceptionAsWarn() throws Exception {
        // Given
        Exception cause = new SSLHandshakeException("missing protocol");
        Exception exception = new DecoderException(cause);
        // When
        serverExceptionHandler.exceptionCaught(ctx, exception);
        // Then
        assertThat(
                logEvents,
                hasItem(
                        startsWith(
                                "WARN Failed while establishing secure connection, cause: missing protocol")));
    }

    @Test
    void shouldLogGenerationExceptionAsWarn() throws Exception {
        // Given
        Exception cause = new GenerationException(new Exception("Cause"));
        Exception exception = new DecoderException(cause);
        // When
        serverExceptionHandler.exceptionCaught(ctx, exception);
        // Then
        assertThat(
                logEvents,
                hasItem(
                        startsWith(
                                "WARN Failed while creating certificate, cause: java.lang.Exception: Cause")));
    }

    @Test
    void shouldLogMissingRootCertificateExceptionAsWarn() throws Exception {
        // Given
        Exception cause = new MissingRootCertificateException("No Root CA cert");
        Exception exception = new DecoderException(cause);
        // When
        serverExceptionHandler.exceptionCaught(ctx, exception);
        // Then
        assertThat(
                logEvents,
                hasItem(
                        startsWith(
                                "WARN Failed while creating certificate, cause: No Root CA cert")));
    }

    @Test
    void shouldLogGenericDecoderExceptionAsError() throws Exception {
        // Given
        Exception exception = new DecoderException("Decoder Exception");
        // When
        serverExceptionHandler.exceptionCaught(ctx, exception);
        // Then
        assertThat(
                logEvents,
                hasItem(
                        startsWith(
                                "ERROR io.netty.handler.codec.DecoderException: Decoder Exception")));
    }

    @Test
    void shouldLogUnknownDecoderExceptionCauseAsError() throws Exception {
        // Given
        Exception cause = new Exception("Unknown Cause");
        Exception exception = new DecoderException(cause);
        // When
        serverExceptionHandler.exceptionCaught(ctx, exception);
        // Then
        assertThat(logEvents, hasItem(startsWith("ERROR java.lang.Exception: Unknown Cause")));
    }

    @Test
    void shouldLogHttpMalformedHeaderExceptionAsWarn() throws Exception {
        // Given
        Exception exception = new HttpMalformedHeaderException("Missing xyz");
        // When
        serverExceptionHandler.exceptionCaught(ctx, exception);
        // Then
        assertThat(logEvents, hasItem(startsWith("WARN Received malformed header: Missing xyz")));
    }

    @Test
    void shouldLogIoExceptionAsDebug() throws Exception {
        // Given
        Exception exception = new IOException("Connection reset by peer");
        // When
        serverExceptionHandler.exceptionCaught(ctx, exception);
        // Then
        assertThat(
                logEvents,
                hasItem(startsWith("DEBUG java.io.IOException: Connection reset by peer")));
    }

    @Test
    void shouldLogGenericExceptionAsError() throws Exception {
        // Given
        Exception exception = new Exception();
        // When
        serverExceptionHandler.exceptionCaught(ctx, exception);
        // Then
        assertThat(logEvents, hasItem(startsWith("ERROR java.lang.Exception")));
    }

    private static List<String> registerLogEvents() {
        List<String> logEvents = new ArrayList<>();
        TestLogAppender logAppender = new TestLogAppender("%p %m%n", logEvents::add);
        LoggerContext context = LoggerContext.getContext();
        LoggerConfig rootLoggerconfig = context.getConfiguration().getRootLogger();
        rootLoggerconfig.getAppenders().values().forEach(context.getRootLogger()::removeAppender);
        rootLoggerconfig.addAppender(logAppender, null, null);
        rootLoggerconfig.setLevel(Level.ALL);
        context.updateLoggers();
        return logEvents;
    }
}
