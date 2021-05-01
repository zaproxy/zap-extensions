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
package org.zaproxy.zap.extension.fuzz;

import java.util.List;
import org.zaproxy.zap.extension.httppanel.Message;

public abstract class AbstractFuzzerTask<M extends Message> implements Runnable {

    private final long id;
    private final AbstractFuzzer<M> parent;
    private final M message;
    private final List<Object> payloads;

    public AbstractFuzzerTask(long id, AbstractFuzzer<M> parent, M message, List<Object> payloads) {
        this.id = id;
        this.parent = parent;
        this.message = message;
        this.payloads = payloads;
    }

    public long getId() {
        return id;
    }

    protected AbstractFuzzer<M> getParent() {
        return parent;
    }

    @Override
    public void run() {
        if (parent.isStopped()) {
            return;
        }

        boolean executedWithErrors = true;
        parent.preTaskExecution(id);
        try {
            runImpl(message, payloads);
            executedWithErrors = false;
        } finally {
            parent.postTaskExecution(id, !executedWithErrors);
        }
    }

    protected abstract void runImpl(M message, List<Object> payloads);
}
