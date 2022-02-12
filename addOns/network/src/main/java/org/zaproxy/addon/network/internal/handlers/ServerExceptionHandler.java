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

import io.netty.channel.ChannelHandler.Sharable;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.timeout.ReadTimeoutException;
import java.io.IOException;
import javax.net.ssl.SSLHandshakeException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.security.MissingRootCertificateException;
import org.zaproxy.addon.network.internal.cert.GenerationException;

/**
 * Handles exceptions caught in the pipeline.
 *
 * <p>Logs the cause appropriately and closes the connection.
 */
@Sharable
public class ServerExceptionHandler extends ChannelInboundHandlerAdapter {

    private static final Logger LOGGER = LogManager.getLogger(ServerExceptionHandler.class);

    private static final ServerExceptionHandler INSTANCE = new ServerExceptionHandler();

    /**
     * Gets the instance of this handler.
     *
     * @return the instance, never {@code null}.
     */
    public static ServerExceptionHandler getInstance() {
        return INSTANCE;
    }

    @Override
    public boolean isSharable() {
        return true;
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        logCause(cause);
        ctx.close();
    }

    private static void logCause(Throwable cause) {
        if (cause instanceof ReadTimeoutException) {
            LOGGER.debug("Timed out while reading message.");
            return;
        }

        if (cause instanceof HttpMalformedHeaderException) {
            LOGGER.warn("Received malformed header: {}", cause.getMessage());
            return;
        }

        if (cause instanceof IOException) {
            LOGGER.debug(cause, cause);
            return;
        }

        if (!(cause instanceof DecoderException)) {
            LOGGER.error(cause, cause);
            return;
        }

        Throwable nestedCause = cause.getCause();
        if (nestedCause == null) {
            LOGGER.error(cause, cause);
            return;
        }

        if (nestedCause instanceof SSLHandshakeException) {
            Level level = Level.WARN;
            String causeMessage = nestedCause.getMessage();
            if (causeMessage != null && causeMessage.contains("unknown_ca")) {
                causeMessage = "the client does not trust ZAP's Root CA Certificate.";
                level = Level.DEBUG;
            }

            LOGGER.log(
                    level, "Failed while establishing secure connection, cause: {}", causeMessage);
            return;
        }

        if (nestedCause instanceof GenerationException
                || nestedCause instanceof MissingRootCertificateException) {
            LOGGER.warn("Failed while creating certificate, cause: {}", nestedCause.getMessage());
            return;
        }

        LOGGER.error(nestedCause, nestedCause);
    }
}
