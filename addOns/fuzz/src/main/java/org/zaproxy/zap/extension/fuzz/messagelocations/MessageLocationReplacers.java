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

import java.util.HashMap;
import java.util.Map;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.model.MessageLocation;

public class MessageLocationReplacers {

    private static MessageLocationReplacers instance;

    private Map<
                    Class<? extends Message>,
                    Map<
                            Class<? extends MessageLocation>,
                            MessageLocationReplacerFactory<? extends Message>>>
            messageLocationReplacers;

    public static MessageLocationReplacers getInstance() {
        if (instance == null) {
            createInstance();
        }
        return instance;
    }

    private static synchronized void createInstance() {
        if (instance == null) {
            instance = new MessageLocationReplacers();
        }
    }

    private MessageLocationReplacers() {
        messageLocationReplacers = new HashMap<>();
    }

    public <T extends Message> void addReplacer(
            Class<T> messageClass, MessageLocationReplacerFactory<T> replacerFactory) {
        Map<Class<? extends MessageLocation>, MessageLocationReplacerFactory<? extends Message>>
                replacers = messageLocationReplacers.get(messageClass);
        if (replacers == null) {
            replacers = new HashMap<>();
            messageLocationReplacers.put(messageClass, replacers);
        }
        replacers.put(replacerFactory.getTargetMessageLocation(), replacerFactory);
    }

    public <T extends Message> void removeReplacer(
            Class<T> messageClass, MessageLocationReplacerFactory<T> replacerFactory) {
        Map<Class<? extends MessageLocation>, MessageLocationReplacerFactory<? extends Message>>
                replacers = messageLocationReplacers.get(messageClass);
        if (replacers == null) {
            return;
        }
        replacers.remove(replacerFactory.getTargetMessageLocation());
        if (replacers.isEmpty()) {
            messageLocationReplacers.remove(messageClass);
        }
    }

    private static <T> T getFactory(
            Map<Class<? extends MessageLocation>, T> factories, Class<?> clazz) {
        if (!MessageLocation.class.isAssignableFrom(clazz)) {
            return null;
        }

        T factory = factories.get(clazz);
        if (factory != null) {
            return factory;
        }

        factory = getFactory(factories, clazz.getSuperclass());
        if (factory != null) {
            return factory;
        }

        for (Class<?> interfaceClazz : clazz.getInterfaces()) {
            factory = getFactory(factories, interfaceClazz);
            if (factory != null) {
                return factory;
            }
        }
        return null;
    }

    public <T extends Message, T1 extends MessageLocation> MessageLocationReplacer<T> getMLR(
            Class<T> messageClass, Class<T1> messageLocationClass) {

        Map<Class<? extends MessageLocation>, MessageLocationReplacerFactory<? extends Message>>
                replacers = messageLocationReplacers.get(messageClass);
        if (replacers != null) {
            @SuppressWarnings("unchecked")
            MessageLocationReplacerFactory<T> replacerFactory =
                    (MessageLocationReplacerFactory<T>) getFactory(replacers, messageLocationClass);
            return replacerFactory.createReplacer();
        }

        return null;
    }
}
