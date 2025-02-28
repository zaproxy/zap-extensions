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
package org.zaproxy.addon.llm.communication;

import dev.langchain4j.model.output.structured.Description;
import lombok.Getter;
import lombok.Setter;

public class Confidence {

    @Description(
            "The level of confidence, typically represented as a percentage or a descriptive term")
    @Getter
    @Setter
    private Integer level;

    @Description("A textual explanation for the assigned confidence level")
    @Getter
    @Setter
    private String explanation;

    public Confidence(Integer level, String explanation) {
        this.level = level;
        this.explanation = explanation;
    }

    @Override
    public String toString() {
        return "Confidence {\n"
                + "level="
                + level
                + "\n"
                + ", explanation='"
                + explanation
                + "\n"
                + "}";
    }
}
