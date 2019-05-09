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

import java.nio.file.Path;
import org.zaproxy.zap.extension.fuzz.payloads.generator.FileStringPayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.generator.StringPayloadGenerator;

public class FuzzerPayloadFileSource extends FuzzerPayloadSource {

    private final Path file;

    /**
     * @param file the file used as source of payloads
     * @throws NullPointerException if {@code file} is {@code null}.
     */
    public FuzzerPayloadFileSource(Path file) {
        super(file.getFileName().toString());
        this.file = file;
    }

    @Override
    public StringPayloadGenerator getPayloadGenerator() {
        return new FileStringPayloadGenerator(file);
    }

    @Override
    public StringPayloadGenerator getPayloadGenerator(int limit) {
        return new FileStringPayloadGenerator(file, limit);
    }
}
