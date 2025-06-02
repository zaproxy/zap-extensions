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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class HttpResponseTagCreatorUnitTest {

    private static final String NO_RESPONSE_MESSAGE = "";
    private static final String RESPONSE_HEADER =
            "HTTP/1.1 200 OK\r\nServer: Apache/1.3.29 (Unix) PHP/4.3.4\r\nContent-Length: 123456\r\nContent-Language: de\r\nContent-Type: text/html\r\n";
    private static final String RESPONSE_BODY =
            "<html>\r\n<head><title>Test</title></head>\r\n<body><h1>MyPage</h1></body>\r\n</html>\r\n";
    private static final String RESPONSE_MESSAGE = RESPONSE_HEADER + "\r\n" + RESPONSE_BODY;
    private static final String NO_MESSAGE_REGEX = "";
    private static final List<String> NO_EXISTING_TAGS = new ArrayList<>();

    @Test
    void whenMatchHeader_ShouldReturnTag() throws Exception {
        MatchByRegexTagRule tagRule = new MatchByRegexTagRule("Server: Apache", "apache");
        HttpResponseTagCreator tagCreator =
                new HttpResponseTagCreator(tagRule, RESPONSE_MESSAGE, NO_EXISTING_TAGS);

        List<String> newTagList = tagCreator.create();

        assertThat(newTagList, containsInAnyOrder("apache"));
    }

    @Test
    void whenMatchBody_ShouldReturnTag() throws Exception {
        MatchByRegexTagRule tagRule = new MatchByRegexTagRule("Test", "tagTest");
        HttpResponseTagCreator tagCreator =
                new HttpResponseTagCreator(tagRule, RESPONSE_MESSAGE, NO_EXISTING_TAGS);

        List<String> newTagList = tagCreator.create();

        assertThat(newTagList, containsInAnyOrder("tagTest"));
    }

    @Test
    void whenMatchHeaderAndBody_ShouldReturnTag() throws Exception {
        MatchByRegexTagRule tagRule =
                new MatchByRegexTagRule("(?s)Server: Apache.*Test", "apacheAndTagTest");
        HttpResponseTagCreator tagCreator =
                new HttpResponseTagCreator(tagRule, RESPONSE_MESSAGE, NO_EXISTING_TAGS);

        List<String> newTagList = tagCreator.create();

        assertThat(newTagList, containsInAnyOrder("apacheAndTagTest"));
    }

    @Test
    void whenMatchAndExistingTags_ShouldReturnAllTags() throws Exception {
        List<String> existingTags = Arrays.asList("tagA", "tagB");
        MatchByRegexTagRule tagRule = new MatchByRegexTagRule("Server: Apache", "apache");
        HttpResponseTagCreator tagCreator =
                new HttpResponseTagCreator(tagRule, RESPONSE_MESSAGE, existingTags);

        List<String> newTagList = tagCreator.create();

        assertThat(newTagList, containsInAnyOrder("tagA", "tagB", "apache"));
    }

    @Test
    void whenNoRegexExists_ShouldReturnExistingTags() throws Exception {
        List<String> existingTags = Arrays.asList("tagA", "tagB");
        MatchByRegexTagRule tagRule = new MatchByRegexTagRule(NO_MESSAGE_REGEX, "tagC");
        HttpResponseTagCreator tagCreator =
                new HttpResponseTagCreator(tagRule, RESPONSE_MESSAGE, existingTags);

        List<String> newTagList = tagCreator.create();

        assertThat(newTagList, containsInAnyOrder("tagB", "tagA"));
    }

    @Test
    void whenNotMatch_ShouldReturnExistingTags() throws Exception {
        List<String> existingTags = Arrays.asList("tagA", "tagB");
        MatchByRegexTagRule tagRule = new MatchByRegexTagRule("NotExisting", "tagC");
        HttpResponseTagCreator tagCreator =
                new HttpResponseTagCreator(tagRule, RESPONSE_MESSAGE, existingTags);

        List<String> newTagList = tagCreator.create();

        assertThat(newTagList, containsInAnyOrder("tagB", "tagA"));
    }

    @Test
    void whenNotMatchDueToMessageEmpty_ShouldReturnExistingTags() throws Exception {
        List<String> existingTags = Arrays.asList("tagA", "tagB");
        MatchByRegexTagRule tagRule = new MatchByRegexTagRule("NotExisting", "tagC");
        HttpResponseTagCreator tagCreator =
                new HttpResponseTagCreator(tagRule, NO_RESPONSE_MESSAGE, existingTags);

        List<String> newTagList = tagCreator.create();

        assertThat(newTagList, containsInAnyOrder("tagB", "tagA"));
    }

    @Test
    void whenNotMatchAndNoExistingTags_ShouldReturnEmptyTags() throws Exception {
        MatchByRegexTagRule tagRule = new MatchByRegexTagRule("NotExisting", "tagC");
        HttpResponseTagCreator tagCreator =
                new HttpResponseTagCreator(tagRule, RESPONSE_MESSAGE, NO_EXISTING_TAGS);

        List<String> newTagList = tagCreator.create();

        assertThat(newTagList, is(empty()));
    }

    @Test
    void whenMatchHeaderByRegex_ShouldReturnTag() throws Exception {
        MatchByRegexTagRule tagRule = new MatchByRegexTagRule("Se.ver.*ache.*29", "tagC");
        HttpResponseTagCreator tagCreator =
                new HttpResponseTagCreator(tagRule, RESPONSE_MESSAGE, NO_EXISTING_TAGS);

        List<String> newTagList = tagCreator.create();

        assertThat(newTagList, containsInAnyOrder("tagC"));
    }

    @Test
    void whenMatchBodyByRegex_ShouldReturnTag() throws Exception {
        MatchByRegexTagRule tagRule = new MatchByRegexTagRule("(?s)Test.*MyPage", "tagC");
        HttpResponseTagCreator tagCreator =
                new HttpResponseTagCreator(tagRule, RESPONSE_MESSAGE, NO_EXISTING_TAGS);

        List<String> newTagList = tagCreator.create();

        assertThat(newTagList, containsInAnyOrder("tagC"));
    }

    @Test
    void whenExtractHeader_ShouldReturnTag() throws Exception {
        ExtractByRegexTagRule tagRule = new ExtractByRegexTagRule("Server: (.*?)\\/.*");
        HttpResponseTagCreator tagCreator =
                new HttpResponseTagCreator(tagRule, RESPONSE_MESSAGE, NO_EXISTING_TAGS);

        List<String> newTagList = tagCreator.create();

        assertThat(newTagList, containsInAnyOrder("Apache"));
    }

    @Test
    void whenExtractWithoutRegex_ShouldReturnEmptyTags() throws Exception {
        ExtractByRegexTagRule tagRule = new ExtractByRegexTagRule("");
        HttpResponseTagCreator tagCreator =
                new HttpResponseTagCreator(tagRule, RESPONSE_MESSAGE, NO_EXISTING_TAGS);

        List<String> newTagList = tagCreator.create();

        assertThat(newTagList, is(empty()));
    }

    @Test
    void whenExtractRegexNothingMatch_ShouldReturnEmptyTags() throws Exception {
        ExtractByRegexTagRule tagRule = new ExtractByRegexTagRule("NotExisting: (.*?)");
        HttpResponseTagCreator tagCreator =
                new HttpResponseTagCreator(tagRule, RESPONSE_MESSAGE, NO_EXISTING_TAGS);

        List<String> newTagList = tagCreator.create();

        assertThat(newTagList, is(empty()));
    }
}
