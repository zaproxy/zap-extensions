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
package org.zaproxy.zap.extension.ascanrules.httputils;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.Source;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.TestUtils;

public class HtmlContextAnalyserUnitTest extends TestUtils {
    private HttpMessage msg;

    @Test
    void shouldGetCorrectParentTag() throws Exception {
        msg = new HttpMessage();
        msg.setRequestHeader("GET /index.html HTTP/1.1");
        msg.setResponseBody("<html><body alert=\"\"></body></html>");
        HtmlContextAnalyser analyser = new HtmlContextAnalyser(msg);
        String catcher = "alert";
        List<HtmlContext> contexts = analyser.getHtmlContexts(catcher, null, 0);
        assertThat(contexts.size(), is(equalTo(1)));
        HtmlContext ctx = contexts.get(0);
        assertThat(ctx.getParentTag(), is(equalTo("body")));
    }

    @Test
    void shouldGetAtrributeNamesAndValues() throws Exception {
        msg = new HttpMessage();
        msg.setRequestHeader("GET /index.html HTTP/1.1");
        msg.setResponseBody("<html><body assert = \"x\" onclick = \"alert('1')\"></body></html>");
        HtmlContextAnalyser analyser = new HtmlContextAnalyser(msg);
        String catcher = "assert = \"x\" onclick = \"alert('1')\"";
        List<HtmlContext> contexts = analyser.getHtmlContexts(catcher, null, 0);
        assertThat(contexts.size(), is(equalTo(1)));
        HtmlContext ctx = contexts.get(0);
        Map<String, String> attrMap = ctx.getTagAttributes();
        assertThat(attrMap.get("assert"), is(equalTo("x")));
        assertThat(attrMap.get("onclick"), is(equalTo("alert('1')")));
    }

    @Test
    void shouldGetAttributeName() throws Exception {
        msg = new HttpMessage();
        msg.setRequestHeader("GET /index.html HTTP/1.1");
        msg.setResponseBody("<html><body assert=\"\"></body></html>");
        HtmlContextAnalyser analyser = new HtmlContextAnalyser(msg);
        String catcher = "assert";
        List<HtmlContext> contexts = analyser.getHtmlContexts(catcher, null, 0);
        assertThat(contexts.size(), is(equalTo(1)));
        HtmlContext ctx = contexts.get(0);
        Map<String, String> attrMap = ctx.getTagAttributes();
        assertThat(ctx.getParentTag(), is(equalTo("body")));
        assertThat(attrMap.get("assert"), is(equalTo("")));
    }

    @Test
    void shouldGetParsedAttributes() {
        String attr = " onclick = \"alert(100)\" accesskey = \"x\" n=\"\"";
        Map<String, String> attrMap = HtmlContextAnalyser.parseAttributes(attr);
        assertThat(attrMap.get("onclick"), is(equalTo("alert(100)")));
        assertThat(attrMap.get("accesskey"), is(equalTo("x")));
        assertThat(attrMap.get("n"), is(equalTo("")));
    }

    @Test
    void shouldGetParsedTags() {
        String tag = "<body onclick = \"alert(100)\" accesskey = \"x\" n=\"\">";
        Map<String, Map<String, String>> tagMap = HtmlContextAnalyser.parseTag(tag);
        Map<String, String> attrMap = tagMap.get("body");
        assertThat(attrMap.get("onclick"), is(equalTo("alert(100)")));
        assertThat(tagMap.get("body").get("accesskey"), is(equalTo("x")));
    }

    @Test
    void shouldParseTagsWithoutCompletion() {
        String tag = "<html> <body> <p accesskey='x' onclick='alert(100)'> Hello </html>";
        Map<String, Map<String, String>> tagMap = HtmlContextAnalyser.parseTag(tag);
        Map<String, String> attrMap = tagMap.get("p");
        assertThat(attrMap.get("onclick"), is(equalTo("alert(100)")));
        assertThat(tagMap.get("p").get("accesskey"), is(equalTo("x")));
    }

    @Test
    void shouldNotRaiseNullPointerException() {
        String tag = "<html> <body> <p accesskey='x' onclick='alert(100)' Hello </html>";
        Map<String, Map<String, String>> tagMap = HtmlContextAnalyser.parseTag(tag);
        assertThat(tagMap.size(), is(equalTo(3)));
        assertThat(tagMap.get("html").size(), is(equalTo(0)));
        assertThat(tagMap.get("p").size(), is(equalTo(2)));
        assertThat(tagMap.get("p").get("Hello"), is(equalTo(null)));
    }

    @Test
    void shouldNotParseComments() {
        String tag =
                "<html> <body> <p accesskey='x' onclick='alert(100)'> Hello <!-- comment --> </html>";
        Map<String, Map<String, String>> tagMap = HtmlContextAnalyser.parseTag(tag);
        assertThat(tagMap.size(), is(equalTo(3)));
        assertThat(tagMap.get("html").size(), is(equalTo(0)));
        assertThat(tagMap.get("p").size(), is(equalTo(2)));
        assertThat(tagMap.get("p").get("Hello"), is(equalTo(null)));
    }

    @Test
    void shouldParseAttributesWithoutQuotesForValues() {
        String attr = " onclick = alert(100) accesskey = x n=\"\" bac = ''";
        Map<String, String> attrMap = HtmlContextAnalyser.parseAttributes(attr);
        assertThat(attrMap.get("onclick"), is(equalTo("alert(100)")));
        assertThat(attrMap.get("accesskey"), is(equalTo("x")));
        assertThat(attrMap.get("n"), is(equalTo("")));
        assertThat(attrMap.get("bac"), is(equalTo("")));
    }

    @Test
    void shouldWorkWhenJerichoDoesnt() {
        // parse using jericho first.. as it is being parsed in HtmlContextAnalyser Code
        String tag = "<html><body><0W45pz4p is 1337></body></html>";
        Source src = new Source(tag);
        Element element = src.getEnclosingElement(0);
        assertThat(element.getChildElements().size(), is(equalTo(1)));

        // parse using parseTag
        Map<String, Map<String, String>> tagMap = HtmlContextAnalyser.parseTag(tag);
        assertThat(tagMap.size(), is(equalTo(3)));

        // parse using jericho but different way of parsing
        List<Element> elements = src.getAllElements();
        assertThat(elements.size(), is(equalTo(2)));
        assertThat(elements.get(0).getName(), is(equalTo("html")));
        assertThat(elements.get(1).getName(), is(equalTo("body")));
    }

    @Test
    void shouldNotBreakParsingTagsInInvalidHtml() {
        String tag = "<html><body><0W45pz4p is 1337</body></html>";
        Map<String, Map<String, String>> tagMap = HtmlContextAnalyser.parseTag(tag);
        assertThat(tagMap.size(), is(equalTo(3)));

        tag = "<html><body><0W45pz4p is 1337 <-- something </body></html>";
        tagMap = HtmlContextAnalyser.parseTag(tag);
        assertThat(tagMap.size(), is(equalTo(3)));
    }

    @Test
    void shouldParseWithUnescapedTagEndChar() {
        String tag = "<html> <body> <span>></span> <a></a> </body> </html>";
        Map<String, Map<String, String>> tagMap = HtmlContextAnalyser.parseTag(tag);
        assertThat(tagMap.size(), is(equalTo(4)));
        assertThat(tagMap.get("html").size(), is(equalTo(0)));
        assertThat(tagMap.get("body").size(), is(equalTo(0)));
        assertThat(tagMap.get("span").size(), is(equalTo(0)));
        assertThat(tagMap.get("a").size(), is(equalTo(0)));
    }
}
