/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2011 The ZAP Development Team
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import net.htmlparser.jericho.Attribute;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.Source;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.network.HttpMessage;

public class HtmlContextAnalyser {

    private char[] quotes = {'\'', '"'};

    // Tag attributes which can contain javascript
    private String[] scriptAttributes = {
        "onBlur",
        "onChange",
        "onClick",
        "onDblClick",
        "onFocus",
        "onKeydown",
        "onKeyup",
        "onKeypress",
        "onLoad",
        "onMousedown",
        "onMouseup",
        "onMouseover",
        "onMousemove",
        "onMouseout",
        "onReset",
        "onSelect",
        "onSubmit",
        "onUnload"
    };

    // Tag attributes which can contain a URL
    private String[] urlAttributes = {
        "action",
        "background",
        "cite",
        "classid",
        "codebase",
        "data",
        "formaction",
        "href",
        "icon",
        "longdesc",
        "manifest",
        "poster",
        "profile",
        "src",
        "usemap",
    };

    // Tags which can have a 'src' attribute
    private String[] tagsWithSrcAttributes = {
        "frame", "iframe", "img",
        "input", // Special case - should also check to see if it has a type of 'image'
        "script", "src",
    };

    private HttpMessage msg = null;
    private String htmlPage = null;
    private Source src = null;

    public HtmlContextAnalyser(HttpMessage msg) {
        this.msg = msg;
        this.htmlPage = msg.getResponseBody().toString();
        src = new Source(htmlPage);
        src.fullSequentialParse();
    }

    private boolean isQuote(char chr) {
        for (int i = 0; i < quotes.length; i++) {
            if (chr == quotes[i]) {
                return true;
            }
        }
        return false;
    }

    private boolean isScriptAttribute(String att) {
        for (int i = 0; i < scriptAttributes.length; i++) {
            if (att.equalsIgnoreCase(scriptAttributes[i])) {
                return true;
            }
        }
        return false;
    }

    private boolean isUrlAttribute(String att) {
        for (int i = 0; i < urlAttributes.length; i++) {
            if (att.equalsIgnoreCase(urlAttributes[i])) {
                return true;
            }
        }
        return false;
    }

    private boolean isInTagWithSrcAttribute(String tag) {
        for (int i = 0; i < tagsWithSrcAttributes.length; i++) {
            if (tag.equalsIgnoreCase(tagsWithSrcAttributes[i])) {
                return true;
            }
        }
        return false;
    }

    public List<HtmlContext> getHtmlContexts(String target) {
        return this.getHtmlContexts(target, null, 0);
    }

    public List<HtmlContext> getHtmlContexts(
            String target, HtmlContext targetContext, int ignoreFlags) {
        return this.getHtmlContexts(target, targetContext, ignoreFlags, false);
    }

    /**
     * Function to parse HTML tags. This can be used for cases where jericho's internal/nested tag
     * parsing fails. There can be multiple tags in the input string so loop through the string and
     * find the tags then parse the attributes and add them to the hashmap. Also adds the tag name
     * or element name to the hashmap. Follows a left to right approach for parsing the tags. Starts
     * at the beginning of the string and looks for the first '<', then looks for the first '>'.
     * Then removes the parsed portion from the string and reiterates.
     *
     * @param input a String containing tags to be parsed
     * @return a Map<String, Map<String,String>> containing element name and hashmap of attributes
     *     and values
     */
    public static Map<String, Map<String, String>> parseTag(String input) {
        Map<String, Map<String, String>> tagMap = new HashMap<>();
        Map<String, String> attMap = new HashMap<>();
        int tagStart = 0;
        int tagEnd = 0;
        int firstSpace = 0;
        String attr = null;
        String tagString = null;
        String tagName = null;

        while (input.length() > 0) {
            tagStart = input.indexOf('<');
            if (tagStart == -1) {
                break;
            }
            tagEnd = input.indexOf('>', tagStart);
            if (tagEnd == -1) {
                break;
            }
            tagString = StringUtils.strip(input.substring(tagStart + 1, tagEnd));
            /** Check if tag string is comment or not. If it is a comment then don't parse it. */
            if (tagString.startsWith("!--")) {
                input = input.substring(tagEnd + 1);
                continue;
            } else if (tagString.charAt(0) != '/') {
                firstSpace = tagString.indexOf(' ');
                if (firstSpace != -1) {
                    tagName =
                            StringUtils.strip(
                                    input.substring(tagStart + 1, tagStart + firstSpace + 1));
                    attr = StringUtils.strip(input.substring(tagStart + firstSpace + 1, tagEnd));
                    attMap = parseAttributes(attr);
                } else {
                    tagName = tagString;
                }
            } else {
                tagName = StringUtils.strip(input.substring(tagStart + 1, tagEnd));
            }
            if (tagName != null && tagName.charAt(0) != '/') {
                tagMap.put(tagName, attMap);
            }
            input = input.substring(tagEnd + 1);
        }
        return tagMap;
    }

    /**
     * Function to parse HTML attributes string. Used specifically for cases where jericho's parsing
     * for internal tags fails.
     *
     * @param attr a String containing attributes to be parsed
     * @return a Map<String, String> containing attribute name and value
     */
    public static Map<String, String> parseAttributes(String attr) {
        Map<String, String> attMap = new HashMap<>();
        String content = attr;
        int attrStart = 0;
        int i = 0;
        String name;
        String value;
        while (content.length() > 0) {
            i = content.indexOf('=', attrStart);
            if (i == -1) {
                break;
            }
            name = StringUtils.strip(content.substring(attrStart, i));
            content = content.substring(i + 1);
            content = StringUtils.strip(content);
            /**
             * The given attribute string may contain attribute and value pairs with double quotes,
             * single quotes or no quotes at all. Example: href="http://www.google.com"
             * onclick=alert(1) img='http://www.google.com'. Since the attribute and value pair is
             * removed after parsing and spaces are being trimmed, it is safe to say that if there
             * is any form of quotes be it single or double for the next value it is at index 0. If
             * this is not the case, it can be said that there aren't any quotes and the value is
             * the rest of the string until a space has been encountered.
             */
            int quoteStart = content.indexOf('"');
            int quoteEnd = content.indexOf('"', quoteStart + 1);
            if (quoteStart != 0 || quoteEnd == -1) {
                quoteStart = content.indexOf("'");
                quoteEnd = content.indexOf("'", quoteStart + 1);
                if (quoteStart != 0 || quoteEnd == -1) {
                    quoteStart = -1;
                    quoteEnd = content.indexOf(' ', quoteStart + 2);
                    if (quoteEnd == -1) {
                        break;
                    }
                }
            }
            value = content.substring(quoteStart + 1, quoteEnd);
            if (value == null) {
                value = "";
            }
            attMap.put(name, value);
            content = content.substring(quoteEnd + 1);
        }
        return attMap;
    }

    public List<HtmlContext> getHtmlContexts(
            String target, HtmlContext targetContext, int ignoreFlags, boolean ignoreSafeParents) {
        List<HtmlContext> contexts = new ArrayList<>();

        int offset = 0;
        while ((offset = htmlPage.indexOf(target, offset)) >= 0) {
            HtmlContext context =
                    new HtmlContext(this.msg, target, offset, offset + target.length());
            offset += target.length();

            // Is it in quotes?
            char leftQuote = 0;
            for (int i = context.getStart() - 1; i > 0; i--) {
                char chr = htmlPage.charAt(i);
                if (isQuote(chr)) {
                    leftQuote = chr;
                    break;
                } else if (chr == '>') {
                    // end of another tag
                    break;
                }
            }
            if (leftQuote != 0) {
                for (int i = context.getEnd(); i < htmlPage.length(); i++) {
                    char chr = htmlPage.charAt(i);
                    if (leftQuote == chr) {
                        // matching quote
                        context.setSurroundingQuote("" + leftQuote);
                        break;
                    } else if (isQuote(chr)) {
                        // Another non matching quote
                        break;
                    } else if (chr == '<') {
                        // start of another tag
                        break;
                    }
                }
            }
            // is it in an HTML comment?
            String prefix = htmlPage.substring(0, context.getStart());
            if (prefix.lastIndexOf("<!--") > prefix.lastIndexOf(">")) {
                // Also check closing comment?
                context.setHtmlComment(true);
            }

            // Work out the location in the DOM
            Element element = src.getEnclosingElement(context.getStart());
            if (element != null) {
                // See if its in an attribute
                boolean isInputTag =
                        element.getName()
                                .equalsIgnoreCase("input"); // Special case for input src attributes
                boolean isImageInputTag = false;
                if (StringUtils.strip(element.getContent().toString()).contains(target)) {
                    Map<String, Map<String, String>> tagMap =
                            parseTag(StringUtils.strip(element.getContent().toString()));
                    for (String tagName : tagMap.keySet()) {
                        if (target.contains(tagName)) {
                            context.setInElementName(true);
                            context.setElementName(tagName);
                            Map<String, String> attMap = tagMap.get(tagName);
                            for (String attName : attMap.keySet()) {
                                if (target.contains(attName)) {
                                    context.setTagAttributes(attName, attMap.get(attName));
                                }
                            }
                        }
                    }
                }

                Iterator<Attribute> iter = element.getAttributes().iterator();
                while (iter.hasNext()) {
                    Attribute att = iter.next();
                    if (att.getValue() != null
                            && att.getValue().toLowerCase().indexOf(target.toLowerCase()) >= 0) {
                        // Found the injected value
                        context.setTagAttribute(att.getName());
                        context.setInUrlAttribute(this.isUrlAttribute(att.getName()));
                        context.setInScriptAttribute(this.isScriptAttribute(att.getName()));
                    } else if (att.getName().equalsIgnoreCase(target)
                            || target.contains(att.getName()) && !context.isInElementName()) {
                        context.setInAttributeName(true);
                        context.setTagAttributes(att.getName(), att.getValue());
                    }
                    if (isInputTag
                            && att.getName().equalsIgnoreCase("type")
                            && "image".equalsIgnoreCase(att.getValue())) {
                        isImageInputTag = true;
                    }
                }

                // record the tag hierarchy
                context.addParentTag(element.getName());
                if (!isInputTag || isImageInputTag) {
                    // Input tags only use the src attribute if the type is 'image'
                    context.setInTagWithSrc(this.isInTagWithSrcAttribute(element.getName()));
                }
                while ((element = element.getParentElement()) != null) {
                    context.addParentTag(element.getName());
                }
            }
            if ((targetContext == null || targetContext.matches(context, ignoreFlags))
                    && (!ignoreSafeParents || !context.isInSafeParentTag())) {
                // Matches the supplied context
                contexts.add(context);
            }
        }

        return contexts;
    }
}
