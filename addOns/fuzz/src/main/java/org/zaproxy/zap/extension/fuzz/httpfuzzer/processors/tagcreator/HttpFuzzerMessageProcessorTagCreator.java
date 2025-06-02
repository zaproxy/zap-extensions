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

import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzResult;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerMessageProcessor;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.HttpFuzzerTaskProcessorUtils;

public class HttpFuzzerMessageProcessorTagCreator implements HttpFuzzerMessageProcessor {

    public static final String NAME =
            Constant.messages.getString("fuzz.httpfuzzer.processor.tagcreator.name");
    public static final String DESCRIPTION =
            Constant.messages.getString("fuzz.httpfuzzer.processor.tagcreator.desc");
    static final String TAG_CREATOR_LIST_STATE_KEY =
            "fuzz.httpfuzzer.messageprocessor.tagcreator.tags.list";
    public static final String TAG_CREATOR_TEXT_STATE_KEY =
            "fuzz.httpfuzzer.messageprocessor.tagcreator.tags.text";
    private static final String TAG_SEPARATOR = "; ";

    private TagRule tagRule;

    public HttpFuzzerMessageProcessorTagCreator(TagRule tagRule) {
        this.tagRule = tagRule;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public HttpMessage processMessage(HttpFuzzerTaskProcessorUtils utils, HttpMessage message) {
        return message;
    }

    @Override
    public boolean processResult(HttpFuzzerTaskProcessorUtils utils, HttpFuzzResult fuzzResult) {
        List<String> tags = createTags(fuzzResult);
        setTagListToCustomState(fuzzResult, tags);
        setTagTextToCustomState(fuzzResult, tags);
        return true;
    }

    private List<String> createTags(HttpFuzzResult fuzzResult) {
        HttpMessage httpMessage = fuzzResult.getHttpMessage();
        List<String> existingTags = getExistingTags(fuzzResult);
        String responseMessage = getResponseMessage(httpMessage);
        HttpResponseTagCreator tagCreator =
                new HttpResponseTagCreator(tagRule, responseMessage, existingTags);
        return tagCreator.create();
    }

    private List<String> getExistingTags(HttpFuzzResult fuzzResult) {
        Map<String, Object> state = fuzzResult.getCustomStates();
        return getExistingTagsFromCustomState(state);
    }

    @SuppressWarnings("unchecked")
    private List<String> getExistingTagsFromCustomState(Map<String, Object> state) {
        if (state.containsKey(TAG_CREATOR_LIST_STATE_KEY)) {
            return (List<String>) state.get(TAG_CREATOR_LIST_STATE_KEY);
        }
        return Collections.emptyList();
    }

    private String getResponseMessage(HttpMessage httpMessage) {
        String responseHeader = httpMessage.getResponseHeader().toString();
        String responseBody = httpMessage.getResponseBody().toString();
        return responseHeader + "\r\n" + responseBody;
    }

    private void setTagListToCustomState(HttpFuzzResult fuzzResult, List<String> tags) {
        fuzzResult.addCustomState(TAG_CREATOR_LIST_STATE_KEY, tags);
    }

    private void setTagTextToCustomState(HttpFuzzResult fuzzResult, List<String> tags) {
        String tagsAsText = joinTagsWithSeparator(tags);
        fuzzResult.addCustomState(TAG_CREATOR_TEXT_STATE_KEY, tagsAsText);
    }

    private String joinTagsWithSeparator(List<String> tags) {
        StringBuilder stringBuilder = new StringBuilder();
        for (String tag : tags) {
            if (stringBuilder.length() > 0) {
                stringBuilder.append(TAG_SEPARATOR);
            }
            stringBuilder.append(tag);
        }
        return stringBuilder.toString();
    }
}
