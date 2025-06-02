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
package org.zaproxy.addon.network.internal.ui;

import java.util.function.Consumer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

public class ConsumerDocumentListener implements DocumentListener {

    private final Consumer<DocumentEvent> consumer;

    public ConsumerDocumentListener(Consumer<DocumentEvent> consumer) {
        this.consumer = consumer;
    }

    @Override
    public void removeUpdate(DocumentEvent e) {
        accept(e);
    }

    @Override
    public void insertUpdate(DocumentEvent e) {
        accept(e);
    }

    @Override
    public void changedUpdate(DocumentEvent e) {
        accept(e);
    }

    private void accept(DocumentEvent e) {
        consumer.accept(e);
    }
}
