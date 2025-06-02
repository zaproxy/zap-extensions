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

import org.zaproxy.zap.extension.fuzz.payloads.generator.StringPayloadGenerator;

public abstract class FuzzerPayloadSource implements Comparable<FuzzerPayloadSource> {

    private final String name;

    public FuzzerPayloadSource(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public abstract StringPayloadGenerator getPayloadGenerator();

    public abstract StringPayloadGenerator getPayloadGenerator(int limit);

    @Override
    public int compareTo(FuzzerPayloadSource other) {
        if (other == null) {
            return 1;
        }
        return getName().compareTo(other.getName());
    }

    @Override
    public String toString() {
        return getName();
    }
}
