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
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.Source;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.testutils.TestUtils;

class HtmlContextAnalyserUnitTest extends TestUtils {
    private HttpMessage msg;

    @Test
    void shouldGetAttributeAndValue() throws Exception {
        // Given
        msg = new HttpMessage();
        msg.setResponseBody("<html><body att=\" Value with target... \"></body></html>");
        HtmlContextAnalyser analyser = new HtmlContextAnalyser(msg);
        String target = "target";
        // When
        List<HtmlContext> contexts = analyser.getHtmlContexts(target, null, 0);
        // Then
        assertThat(contexts, hasSize(1));
        HtmlContext ctx = contexts.get(0);
        assertThat(ctx.getTagAttribute(), is(equalTo("att")));
        assertThat(ctx.getTagAttributeValue(), is(equalTo(" Value with target... ")));
    }

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

    @Test
    void shouldParseWithNoQuotes() throws Exception {
        String catcher = "hg4378as";
        msg = new HttpMessage();
        msg.setRequestHeader("GET /index.html HTTP/1.1");
        msg.setResponseBody("<html> <body> <span id=" + catcher + ">hello</span> </body> </html>");
        HtmlContextAnalyser analyser = new HtmlContextAnalyser(msg);
        List<HtmlContext> contexts = analyser.getHtmlContexts(catcher, null, 0);
        assertThat(contexts.size(), is(equalTo(1)));
        HtmlContext ctx = contexts.get(0);
        assertThat(ctx.getParentTag(), is(equalTo("span")));
        assertThat(ctx.getSurroundingQuote(), is(equalTo("")));
    }

    @Test
    void shouldParseTheCorrectSurroundingQuotesForTagAttributesWithMixedQuotes() throws Exception {
        String catcher = "hg4378as";
        msg = new HttpMessage();
        msg.setRequestHeader("GET /index.html HTTP/1.1");
        msg.setResponseBody(
                "<html> <body> <span id='{\"entity\": \""
                        + catcher
                        + "\"}'>hello</span> <a></a> </body> </html>");
        HtmlContextAnalyser analyser = new HtmlContextAnalyser(msg);
        List<HtmlContext> contexts = analyser.getHtmlContexts(catcher, null, 0);
        assertThat(contexts.size(), is(equalTo(1)));
        HtmlContext ctx = contexts.get(0);
        assertThat(ctx.getParentTag(), is(equalTo("span")));
        assertThat(ctx.getSurroundingQuote(), is(equalTo("\'")));
    }

    @Test
    void shouldParseTheCorrectAttribute() throws Exception {
        String catcher = "hg4378as";
        msg = new HttpMessage();
        msg.setRequestHeader("GET /index.html HTTP/1.1");
        msg.setResponseBody(
                "<html> <body> <span id='{\"entity\": \""
                        + catcher
                        + "\"}' name=\""
                        + catcher
                        + "\">hello</span> <a></a> </body> </html>");
        HtmlContextAnalyser analyser = new HtmlContextAnalyser(msg);
        List<HtmlContext> contexts = analyser.getHtmlContexts(catcher, null, 0);
        assertThat(contexts.size(), is(equalTo(2)));

        HtmlContext ctx1 = contexts.get(0);
        assertThat(ctx1.getParentTag(), is(equalTo("span")));
        assertThat(ctx1.getTagAttribute(), is(equalTo("id")));
        assertThat(ctx1.getSurroundingQuote(), is(equalTo("'")));

        HtmlContext ctx2 = contexts.get(1);
        assertThat(ctx2.getParentTag(), is(equalTo("span")));
        assertThat(ctx2.getTagAttribute(), is(equalTo("name")));
        assertThat(ctx2.getSurroundingQuote(), is(equalTo("\"")));
    }

    @Test
    void shouldParseEvalWithHtmlEscapingContext() throws Exception {
        // Given - Case 1: eval() with HTML escaping (Firing Range scenario)
        // This tests whether HtmlContextAnalyser can parse HTML where user input
        // is placed inside eval() with HTML entity escaping applied in the template.
        // The payload ";alert(1);" is injected, resulting in:
        // <script>eval(';alert(1);'.replace(/</g, '&lt;')...)</script>
        String payload = ";alert(1);";
        msg = new HttpMessage();
        msg.setRequestHeader("GET /test?q=" + payload + " HTTP/1.1");
        msg.setResponseBody(
                "<html>\n"
                        + "  <body>\n"
                        + "    <script>eval('"
                        + payload
                        + "'.replace(/</g, '&lt;')\n"
                        + "                              .replace(/&/g, '&amp;')\n"
                        + "                              .replace(/>/g, '&gt;'));\n"
                        + "    </script>\n"
                        + "  </body>\n"
                        + "</html>");

        // When
        HtmlContextAnalyser analyser = new HtmlContextAnalyser(msg);
        List<HtmlContext> contexts = analyser.getHtmlContexts(payload, null, 0);

        // Then - Verify the parser can find the payload in the script context
        // The payload should be detected inside the script tag
        assertThat(contexts, hasSize(1));
        HtmlContext ctx = contexts.get(0);
        assertThat(ctx.getParentTag(), is(equalTo("script")));
        // The target should be found in the innerHTML/text content of the script tag
        assertThat(ctx.isInScriptAttribute(), is(equalTo(false)));
    }

    @Test
    void shouldParseEvalEscapeScriptBreakingContext() throws Exception {
        // Given - Case 2: eval(escape()) with script-breaking payload (Firing Range scenario)
        // This tests whether HtmlContextAnalyser correctly parses HTML when a payload
        // breaks out of a script tag using </script>. The critical question is:
        // Does the HTML parser treat </script> inside a string literal as an HTML boundary?
        // According to HTML spec, it should - HTML parsing happens BEFORE JS execution.
        //
        // Input: </script><scrIpt>alert(1);</scRipt><script>
        // Results in: <script>eval(escape('</script><scrIpt>alert(1);</scRipt><script>'));</script>
        //
        // Expected parser behavior (per HTML spec):
        // 1. <script>eval(escape('</script> - First script element (broken/incomplete)
        // 2. <scrIpt>alert(1);</scRipt> - Second script element (EXECUTABLE XSS)
        // 3. <script>'));</script> - Third script element (syntax error but parsed)
        String payload = "</script><scrIpt>alert(1);</scRipt><script>";
        msg = new HttpMessage();
        msg.setRequestHeader("GET /test?q=" + payload + " HTTP/1.1");
        msg.setResponseBody(
                "<html>\n"
                        + "  <body>\n"
                        + "    <script>\n"
                        + "      eval(escape('"
                        + payload
                        + "'));\n"
                        + "    </script>\n"
                        + "  </body>\n"
                        + "</html>");

        // When
        HtmlContextAnalyser analyser = new HtmlContextAnalyser(msg);

        // Search for the malicious payload that actually executes
        String maliciousPayload = "alert(1);";
        List<HtmlContext> contexts = analyser.getHtmlContexts(maliciousPayload, null, 0);

        // Then - Verify the parser detects the standalone malicious script element
        // If the HTML parser correctly fragments the response, we should find
        // "alert(1);" inside its own script element (case-insensitive "scrIpt")
        assertThat(contexts, hasSize(1));
        HtmlContext ctx = contexts.get(0);
        assertThat(ctx.getParentTag().toLowerCase(), is(equalTo("script")));

        // Verify this is detected as script content, not an attribute
        assertThat(ctx.isInScriptAttribute(), is(equalTo(false)));
    }

    @Test
    void shouldDetectMultipleScriptElementsAfterScriptBreaking() throws Exception {
        // Given - Verify that Jericho HTML parser creates multiple script elements
        // when </script> appears in the middle of a string literal
        String payload = "</script><scrIpt>alert(1);</scRipt><script>";
        msg = new HttpMessage();
        msg.setRequestHeader("GET /test?q=" + payload + " HTTP/1.1");
        msg.setResponseBody(
                "<html>\n"
                        + "  <body>\n"
                        + "    <script>\n"
                        + "      eval(escape('"
                        + payload
                        + "'));\n"
                        + "    </script>\n"
                        + "  </body>\n"
                        + "</html>");

        // When - Parse the HTML using Jericho (same parser HtmlContextAnalyser uses)
        Source src = new Source(msg.getResponseBody().toString());
        src.fullSequentialParse();
        List<Element> scriptElements = src.getAllElements("script");

        // Then - We expect to see multiple script elements due to the </script> tag
        // breaking out of the original script context
        // Expected: 3 script elements total
        // 1. <script>eval(escape('</script> - broken/incomplete
        // 2. <scrIpt>alert(1);</scRipt> - injected malicious script
        // 3. <script>'));</script> - broken/incomplete
        assertThat(scriptElements.size(), is(equalTo(3)));

        // Verify the middle element contains our malicious payload
        Element maliciousScript = scriptElements.get(1);
        String scriptContent = maliciousScript.getContent().toString();
        assertThat(scriptContent, is(equalTo("alert(1);")));
    }
}
