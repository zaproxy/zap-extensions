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

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.handler.timeout.ReadTimeoutException;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import org.zaproxy.addon.network.internal.ChannelAttributes;

/**
 * Handles read timeouts.
 *
 * <p>Fires a {@link ReadTimeoutException} when a timeout occurs and if no message is being
 * processed, as indicated by {@link ChannelAttributes#PROCESSING_MESSAGE}.
 */
public class ReadTimeoutHandler extends IdleStateHandler {

    /**
     * Constructs a {@code ReadTimeoutHandler} with the given timeout and unit.
     *
     * @param timeout the value to timeout.
     * @param unit the time unit.
     * @throws IllegalArgumentException if the timeout is less or equal to zero.
     * @throws NullPointerException if the given {@code unit} is {@code null}.
     */
    public ReadTimeoutHandler(int timeout, TimeUnit unit) {
        super(validate(timeout), 0, 0, Objects.requireNonNull(unit));
    }

    private static int validate(int timeout) {
        if (timeout <= 0) {
            throw new IllegalArgumentException("The timeout value must be greater than 0.");
        }
        return timeout;
    }

    @Override
    protected final void channelIdle(ChannelHandlerContext ctx, IdleStateEvent evt)
            throws Exception {
        if (!ctx.channel().attr(ChannelAttributes.PROCESSING_MESSAGE).get()) {
            ctx.fireExceptionCaught(ReadTimeoutException.INSTANCE);
        }
    }
}
