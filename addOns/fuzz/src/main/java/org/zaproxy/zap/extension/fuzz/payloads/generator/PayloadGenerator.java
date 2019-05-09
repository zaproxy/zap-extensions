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
package org.zaproxy.zap.extension.fuzz.payloads.generator;

import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

public interface PayloadGenerator<E extends Payload> extends Iterable<E> {

    final long UNKNOWN_NUMBER_OF_PAYLOADS = 0;

    /**
     * Returns the number of payloads that can be generated, or {@value #UNKNOWN_NUMBER_OF_PAYLOADS}
     * if unknown. Used as a hint for calculation of progress.
     *
     * @return the number of payloads that can be generated, or {@value #UNKNOWN_NUMBER_OF_PAYLOADS}
     *     if unknown.
     * @see #UNKNOWN_NUMBER_OF_PAYLOADS
     */
    long getNumberOfPayloads();

    /**
     * Returns an iterator over a set of payloads.
     *
     * <p>Whenever possible and for performance reasons (i.e. memory constraints) the payloads
     * should be generated when required.
     *
     * <p><strong>Note:</strong> The generators are expected to throw {@code
     * PayloadGenerationException} if an error occurs while generating the payload, during the call
     * to {@code Iterator.next()}. Any other {@code Exception} thrown should be treated as an error
     * (potentially a bug) by consumers of the generated payloads (for example, might log the
     * exception as error).
     *
     * @see java.util.Iterator#next()
     * @see PayloadGenerationException
     */
    @Override
    public ResettableAutoCloseableIterator<E> iterator();

    /**
     * Returns a copy of this payload generator.
     *
     * <p>Implementations might opt to return {@code this}, if immutable and thread-safe.
     *
     * @return a new {@code PayloadGenerator} whose contents are equal to this payload generator.
     */
    PayloadGenerator<E> copy();
}
