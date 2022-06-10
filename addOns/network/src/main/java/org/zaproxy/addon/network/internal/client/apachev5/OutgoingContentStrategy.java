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

import org.apache.hc.core5.http.ContentLengthStrategy;
import org.apache.hc.core5.http.HttpEntityContainer;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpMessage;
import org.apache.hc.core5.http.impl.DefaultContentLengthStrategy;

/**
 * A {@link ContentLengthStrategy} that always determines the length based on the contained entity.
 */
public class OutgoingContentStrategy implements ContentLengthStrategy {

    @Override
    public long determineLength(HttpMessage message) throws HttpException {
        if (message instanceof HttpEntityContainer) {
            return ((HttpEntityContainer) message).getEntity().getContentLength();
        }
        return DefaultContentLengthStrategy.INSTANCE.determineLength(message);
    }
}
