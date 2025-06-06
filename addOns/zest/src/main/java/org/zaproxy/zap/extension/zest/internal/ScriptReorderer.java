/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.zest.internal;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;
import lombok.AllArgsConstructor;
import lombok.Getter;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.zest.ZestStatementFromJson;
import org.zaproxy.zest.core.v1.ZestStatement;

/**
 * This class checks the order of added ZestStatements and makes sure the order is maintained based
 * on their indexes. When recording client side scripts in ZAP the statements are added via API
 * calls and can end up in the wrong order depending on how quickly they are processed.
 */
public class ScriptReorderer {

    private Consumer<ZestStatement> consumer;
    private int lastIndex;

    private List<OrderedZestStatement> orderedStatements = new ArrayList<>();

    private static final Logger LOGGER = LogManager.getLogger(ScriptReorderer.class);

    public ScriptReorderer(Consumer<ZestStatement> consumer) {
        this.consumer = consumer;
    }

    public synchronized void recordStatement(JSONObject json) throws Exception {
        orderedStatements.add(
                new OrderedZestStatement(
                        json.getInt("index"),
                        ZestStatementFromJson.createZestStatementFromJson(json)));
        process();
    }

    private void process() {
        Collections.sort(orderedStatements);
        if (orderedStatements.size() == 5) {
            // This is unexpected and is likely to indicate a problem
            LOGGER.error(
                    "List of cached statements is 5 which typically indicates a problem, indexes are {}",
                    orderedStatements.stream().map(OrderedZestStatement::getIndex).toList());
        }

        while (!orderedStatements.isEmpty()
                && orderedStatements.get(0).getIndex() == lastIndex + 1) {
            OrderedZestStatement ostmt = orderedStatements.remove(0);
            consumer.accept(ostmt.getStatement());
            lastIndex++;
        }
    }

    @Getter
    @AllArgsConstructor
    private static class OrderedZestStatement implements Comparable<OrderedZestStatement> {
        private int index;
        private ZestStatement statement;

        @Override
        public int compareTo(OrderedZestStatement o) {
            return Integer.compare(index, o.getIndex());
        }
    }
}
