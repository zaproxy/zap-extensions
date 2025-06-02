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
package org.zaproxy.zap.extension.fuzz.messagelocations;

import java.util.SortedSet;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.model.InvalidMessageException;
import org.zaproxy.zap.model.MessageLocationConsumer;

public interface MessageLocationReplacer<T extends Message> extends MessageLocationConsumer {

    /**
     * Initialises the replacer with the given {@code message}. The message will be used as
     * source/base for replacements.
     *
     * @param message the source message, that will be used in the invocations of {@code replace}
     *     method
     */
    void init(T message);

    /**
     * Returns a message, based on the previously initialised message, with the {@code locations}
     * replaced with the given {@code values}.
     *
     * @param replacements the locations and its values used to replace, or insert into, the
     *     corresponding location
     * @return a message with the given {@code locations} replaced with the given {@code values}
     * @throws InvalidMessageException if any of the changes led to an invalid message
     * @throws IllegalArgumentException if the {@code values} are not of an allowed type or are not
     *     valid
     * @throws IllegalStateException if the replacer was not initialised
     */
    T replace(SortedSet<? extends MessageLocationReplacement<?>> replacements)
            throws InvalidMessageException;
}
