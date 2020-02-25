/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.payloads;

import java.util.Collection;
import java.util.Iterator;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

public class PayloadCollectionIterator<E extends Payload>
        implements ResettableAutoCloseableIterator<E> {

    private final Collection<E> payloads;
    private Iterator<E> payloadIterator;

    public PayloadCollectionIterator(Collection<E> payloads) {
        this.payloads = payloads;

        initIterator();
    }

    private void initIterator() {
        payloadIterator = payloads.iterator();
    }

    @Override
    public boolean hasNext() {
        return payloadIterator.hasNext();
    }

    @Override
    public E next() {
        return payloadIterator.next();
    }

    @Override
    public void remove() {}

    @Override
    public void reset() {
        initIterator();
    }

    @Override
    public void close() {}
}
