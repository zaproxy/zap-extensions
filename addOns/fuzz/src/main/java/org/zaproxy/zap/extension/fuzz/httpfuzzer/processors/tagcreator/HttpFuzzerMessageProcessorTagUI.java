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
package org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.tagcreator;

import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessorUI;

public class HttpFuzzerMessageProcessorTagUI
        implements HttpFuzzerMessageProcessorUI<HttpFuzzerMessageProcessorTagCreator> {

    private static final String NAME = HttpFuzzerMessageProcessorTagCreator.NAME;
    private static final String DESCRIPTION = HttpFuzzerMessageProcessorTagCreator.DESCRIPTION;
    private TagRule tagRule;

    public HttpFuzzerMessageProcessorTagUI(TagRule tagRule) {
        this.tagRule = tagRule;
    }

    public TagRule getTagRule() {
        return tagRule;
    }

    @Override
    public boolean isMutable() {
        return true;
    }

    @Override
    public String getName() {
        String ruleName = tagRule.getName();
        if (ruleName != null) {
            return NAME + ": " + ruleName;
        }
        return NAME;
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    @Override
    public HttpFuzzerMessageProcessorTagCreator getFuzzerMessageProcessor() {
        return new HttpFuzzerMessageProcessorTagCreator(tagRule);
    }

    @Override
    public HttpFuzzerMessageProcessorTagUI copy() {
        return new HttpFuzzerMessageProcessorTagUI(tagRule);
    }
}
