/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.codec;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandler.Sharable;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

/** Encodes the header and body contained in a {@link HttpMessage}. */
@Sharable
abstract class HttpMessageEncoder extends MessageToByteEncoder<HttpMessage> {

    private static final int CRLF = '\r' << 8 | '\n';

    private static final Charset HEADER_CHARSET = StandardCharsets.UTF_8;

    private final Function<HttpMessage, HttpHeader> headerProvider;
    private final Function<HttpMessage, HttpBody> bodyProvider;

    HttpMessageEncoder(
            Function<HttpMessage, HttpHeader> headerProvider,
            Function<HttpMessage, HttpBody> bodyProvider) {
        super(HttpMessage.class);
        this.headerProvider = headerProvider;
        this.bodyProvider = bodyProvider;
    }

    @Override
    public boolean isSharable() {
        return true;
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, HttpMessage msg, ByteBuf out) {
        HttpHeader header = headerProvider.apply(msg);

        out.writeCharSequence(header.getPrimeHeader(), HEADER_CHARSET);
        ByteBufUtil.writeShortBE(out, CRLF);

        out.writeCharSequence(header.getHeadersAsString(), HEADER_CHARSET);
        ByteBufUtil.writeShortBE(out, CRLF);

        HttpBody body = bodyProvider.apply(msg);
        if (body.length() != 0) {
            out.writeBytes(body.getBytes());
        }
    }
}
