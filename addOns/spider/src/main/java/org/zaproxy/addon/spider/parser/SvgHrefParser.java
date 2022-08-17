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
package org.zaproxy.addon.spider.parser;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.logging.log4j.LogManager;
import org.parosproxy.paros.network.HttpMessage;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXParseException;
import org.zaproxy.addon.spider.UrlCanonicalizer;
import org.zaproxy.zap.utils.XmlUtils;

public class SvgHrefParser extends SpiderParser {
    private static final Pattern PATTERN_SVG_EXTENSION =
            Pattern.compile("\\.svg\\z", Pattern.CASE_INSENSITIVE);
    private static final String HREF_EXPRESSION = "//*[@href or @HREF]";
    private static final String[] ATTRIBUTE_NAMES = {"href", "HREF", "xlink:href", "XLINK:HREF"};
    private static final String SVG_TAG = "SVG";
    private static final String IMAGE_TAG = "IMAGE";

    private static XPathExpression xpathHrefExpression;

    static {
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            xpathHrefExpression = xpath.compile(HREF_EXPRESSION);
        } catch (XPathExpressionException e) {
            LogManager.getLogger(SvgHrefParser.class).error(e);
        }
    }

    private static DocumentBuilder documentBuilder;

    static {
        try {
            documentBuilder = XmlUtils.newXxeDisabledDocumentBuilderFactory().newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            LogManager.getLogger(SvgHrefParser.class)
                    .warn("An error occurred while getting the DocumentBuilder", e);
        }
    }

    @Override
    public boolean parseResource(HttpMessage message, Source source, int depth) {
        String baseUrl = message.getRequestHeader().getURI().toString();
        getLogger().debug("SVG Spider attempting to parse {}", baseUrl);

        if (isSvg(message)) {
            try {
                synchronized (documentBuilder) {
                    Document xmldoc =
                            documentBuilder.parse(
                                    new InputSource(
                                            new ByteArrayInputStream(
                                                    message.getResponseBody().getBytes())));
                    NodeList hrefNodes =
                            (NodeList) xpathHrefExpression.evaluate(xmldoc, XPathConstants.NODESET);
                    if (hrefNodes.getLength() > 0) {
                        processNodeList(hrefNodes, message, depth, baseUrl);
                        return true;
                    } else {
                        return false;
                    }
                }
            } catch (SAXParseException spe) {
                if (spe.getMessage().contains("DOCTYPE is disallowed")) {
                    getLogger()
                            .debug(
                                    "Skipping {} due to XXE safety and DOCTYPE declaration present.",
                                    baseUrl);
                } else {
                    getLogger().warn("An error occurred trying to parse {}", baseUrl, spe);
                }
                return false;
            } catch (Exception e) {
                getLogger().warn("An error occurred trying to parse {}", baseUrl, e);
                return false;
            }
        } else if (containsSvg(message, () -> source)) {
            List<Element> svgElements = source.getAllElements(SVG_TAG);
            return processSvgElements(message, source, depth, baseUrl, svgElements);
        }
        return false;
    }

    private boolean processSvgElements(
            HttpMessage message,
            Source source,
            int depth,
            String baseUrl,
            List<Element> svgElements) {
        if (svgElements.isEmpty()) {
            return false;
        }
        // Try to see if there's any BASE tag that could change the base URL
        Element base = source.getFirstElement(HTMLElementName.BASE);
        if (base != null) {
            getLogger().debug("Base tag was found in HTML: {}", base.getDebugInfo());
            String href = base.getAttributeValue("href");
            if (href != null && !href.isEmpty()) {
                baseUrl = UrlCanonicalizer.getCanonicalURL(href, baseUrl);
            }
        }
        return processSvgTags(message, depth, baseUrl, svgElements, IMAGE_TAG)
                || processSvgTags(message, depth, baseUrl, svgElements, HTMLElementName.SCRIPT);
    }

    private boolean processSvgTags(
            HttpMessage message,
            int depth,
            String baseUrl,
            List<Element> svgElements,
            String subTag) {
        boolean found = false;
        for (Element el : svgElements) {
            for (Element imageTag : el.getAllElements(subTag)) {
                for (String attribute : ATTRIBUTE_NAMES) {
                    String hrefCandidate = imageTag.getAttributeValue(attribute);
                    if (hrefCandidate != null && !hrefCandidate.isEmpty()) {
                        processURL(message, depth, hrefCandidate, baseUrl);
                        found = true;
                        break;
                    }
                }
            }
        }
        return found;
    }

    private void processNodeList(NodeList nodes, HttpMessage message, int depth, String baseUrl) {
        getLogger()
                .debug(
                        "Identified {} nodes with href attribute from: {}",
                        nodes.getLength(),
                        baseUrl);
        for (int i = 0; i < nodes.getLength(); i++) {
            String extractedUrl = extractUrl(nodes.item(i));
            if (!extractedUrl.isEmpty()) {
                URI newUri = null;
                try {
                    newUri = new URI(baseUrl).resolve(extractedUrl);
                } catch (URISyntaxException e) {
                    getLogger()
                            .warn(
                                    "Failed to resolve extracted URL: {} against base URL: {}",
                                    extractedUrl,
                                    baseUrl);
                }
                getLogger().debug("Resolved URL: {} from: {}", newUri, baseUrl);
                if (newUri != null && newUri.isAbsolute()) {
                    processURL(message, depth, extractedUrl, baseUrl);
                }
            }
        }
    }

    private static String extractUrl(Node node) {
        String extractedUrl = "";
        for (String attributeName : ATTRIBUTE_NAMES) {
            try {
                extractedUrl = node.getAttributes().getNamedItem(attributeName).getNodeValue();
                if (!extractedUrl.isEmpty()) {
                    break;
                }
            } catch (NullPointerException npe) {
                // ignore
            }
        }
        return extractedUrl;
    }

    @Override
    public boolean canParseResource(HttpMessage message, String path, boolean wasAlreadyConsumed) {
        return isSvg(message)
                || containsSvg(message, () -> new Source(message.getResponseBody().toString()));
    }

    private static boolean containsSvg(HttpMessage message, Supplier<Source> source) {
        return message.getResponseHeader().isHtml()
                && source.get().getFirstElement(SVG_TAG) != null;
    }

    private static boolean isSvg(HttpMessage msg) {
        if (msg.getResponseHeader().hasContentType("svg")) {
            return true;
        }

        String path = msg.getRequestHeader().getURI().getEscapedPath();
        if (path != null) {
            return PATTERN_SVG_EXTENSION.matcher(path).find();
        }
        return false;
    }
}
