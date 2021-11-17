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

import io.netty.channel.ChannelHandler.Sharable;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Encodes the response contained in a {@link HttpMessage}.
 *
 * @see #getInstance()
 */
@Sharable
public class HttpResponseEncoder extends HttpMessageEncoder {

    private static final HttpResponseEncoder INSTANCE = new HttpResponseEncoder();

    HttpResponseEncoder() {
        super(HttpMessage::getResponseHeader, HttpMessage::getResponseBody);
    }

    /**
     * Gets the instance of the encoder.
     *
     * @return the instance, never {@code null}.
     */
    public static HttpResponseEncoder getInstance() {
        return INSTANCE;
    }
}
