/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.csphelper;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Attribute;
import net.htmlparser.jericho.Attributes;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

public class CspHelper {

    private static final Logger LOGGER = Logger.getLogger(CSP.class);
    private ExtensionCspHelper ext;
    private String[] jsEventAttrs = {
        "onafterprint",
        "onbeforeprint",
        "onbeforeunload",
        "onerror",
        "onhashchange",
        "onload",
        "onmessage",
        "onoffline",
        "ononline",
        "onpagehide",
        "onpageshow",
        "onpopstate",
        "onresize",
        "onstorage",
        "onunload",
        "onblur",
        "onchange",
        "oncontextmenu",
        "onfocus",
        "oninput",
        "oninvalid",
        "onreset",
        "onsearch",
        "onselect",
        "onsubmit",
        "onkeydown",
        "onkeypress",
        "onkeyup",
        "onclick",
        "ondblclick",
        "ondrag",
        "ondragend",
        "ondragenter",
        "ondragleave",
        "ondragover",
        "ondragstart",
        "ondrop",
        "onmousedown",
        "onmousemove",
        "onmouseout",
        "onmouseover",
        "onmouseup",
        "onmousewheel",
        "onscroll",
        "onwheel",
        "oncopy",
        "oncut",
        "onpaste",
        "onabort",
        "oncanplay",
        "oncanplaythrough",
        "oncuechange",
        "ondurationchange",
        "onemptied",
        "onended",
        "onloadeddata",
        "onloadedmetadata",
        "onloadstart",
        "onpause",
        "onplay",
        "onplaying",
        "onprogress",
        "onratechange",
        "onseeked",
        "onseeking",
        "onstalled",
        "onsuspend",
        "ontimeupdate",
        "onvolumechange",
        "onwaiting",
        "onshow",
        "ontoggle"
    };

    private static final int LINK_TYPE_REQUEST = 1;
    private static final int LINK_TYPE_IMAGE = 2;
    private static final int LINK_TYPE_SCRIPT = 3;
    private static final int LINK_TYPE_STYLE = 4;

    public CspHelper(ExtensionCspHelper extension) {
        this.ext = extension;
    }

    private void parseDirective(CSP csp, HttpMessage msg, Source source, String directive) {

        LOGGER.debug("Processing CSP directive: " + directive);
        switch (directive) {
            case "base-uri":
                handleBaseUri(csp, msg, source);
                break;
            case "script-src":
                handleScripts(csp, msg, source);
                break;
            case "img-src":
                handleImages(csp, msg, source);
                break;
            case "font-src":
                handleFonts(csp, msg, source);
                break;
            case "style-src":
                // External styles processed by handleLinks()
                handleInlineStyles(csp, msg, source);
                break;
            case "media-src":
                handleMedia(csp, msg, source);
                break;
            case "object-src":
                handleObjects(csp, msg, source);
                break;
            case "frame-src":
                handleFrames(csp, msg, source);
                break;
            case "child-src":
                // Noop, processed by handleFrames()
                break;
            case "manifest-src":
                // Noop, processed by handleLinks()
                break;
            case "connect-src":
                // Noop, processed by handleScripts()
                break;
            case "worker-src":
                // Noop, processed by handleScripts()
                break;
            case "frame-ancestors":
                // TODO: User defined?
                break;
            case "form-action":
                handleForms(csp, msg, source);
                break;
            case "upgrade-insecure-requests":
                // TODO: User defined?
                break;
            case "block-mixed-content":
                // TODO: User defined?
                break;
            case "disown-opener":
                // TODO: CSP3
                break;
            case "require-sri-for":
                // TODO: User defined?
                break;
            case "sandbox":
                // TODO: User defined?
                break;
            case "reflected-xss":
                // TODO: User defined?
                break;
            case "plugin-types":
                // Noop, processed by parse()
                break;
            case "referrer":
                // TODO: User defined?
                break;
            case "report-only":
                // TODO: User defined?
                break;
            case "report-to":
                // TODO: User defined?
                break;
            default:
                break;
        }
    }

    private void handleBaseUri(CSP csp, HttpMessage msg, Source source) {
        // Set the base-uri
        csp.getBaseUri().addExtra(msg.getRequestHeader().getURI().toString());
    }

    private void handleInlineStyles(CSP csp, HttpMessage msg, Source source) {
        // Style tags
        List<Element> styles = source.getAllElements("style");
        LOGGER.debug("Got styles " + styles.size());
        for (Element style : styles) {
            String src = style.getAttributeValue("src");
            if (src == null) {
                String content = style.getContent().toString();
                // Handle inline styles
                csp.getStyleSource().addHashNonce("'" + ExtensionCspHelper.sha256(content) + "'");
                LOGGER.debug(
                        "Adding style hash "
                                + ExtensionCspHelper.sha256(style.getContent().toString())
                                + " ("
                                + content
                                + ")");
                handleStyleLinks(content, csp);
            }
        }
    }

    private void handleStyleLinks(String content, CSP csp) {
        ArrayList<String> styleLinks =
                regexGetGroup(
                        "url\\([\"']?((http[s]?:\\/\\/)?\\w+\\.\\w[\\.\\w/?=&]+)[\"']?",
                        1,
                        content);
        for (String link : styleLinks) {
            switch (getLinkType(link)) {
                case LINK_TYPE_IMAGE:
                    csp.getImageSource().addUrl(link);
                    break;
                case LINK_TYPE_STYLE:
                    csp.getStyleSource().addUrl(link);
                    break;
                default:
                    break;
            }
        }
    }

    private int getLinkType(String link) {
        if (link.toLowerCase().matches("\\.(png|jpg|jpeg|gif|tiff|bmp|svg)[\\w?=&]*$")) {
            return LINK_TYPE_IMAGE;
        }
        if (link.toLowerCase().matches("\\.(css)[\\w?=&]*$")) {
            return LINK_TYPE_STYLE;
        }
        if (link.toLowerCase().matches("\\.(js)[\\w?=&]*$")) {
            return LINK_TYPE_SCRIPT;
        }
        return LINK_TYPE_REQUEST;
    }

    private void handleJsAttr(CSP csp, Source content) {
        List<Element> tags = content.getAllElements();
        for (Element tag : tags) {
            Attributes tagAttr = tag.getAttributes();
            if (tagAttr != null) {
                for (String attr : this.jsEventAttrs) {
                    Attribute jsAttr = tagAttr.get(attr);
                    if (jsAttr != null) {
                        csp.getScriptSource()
                                .addHashNonce(
                                        "'" + ExtensionCspHelper.sha256(jsAttr.getValue()) + "'");
                        LOGGER.debug(
                                "SBSB adding JS attr hash "
                                        + ExtensionCspHelper.sha256(jsAttr.getValue())
                                        + " ("
                                        + jsAttr.getValue()
                                        + ")");
                    }
                }
            }
        }
    }

    private void handleScripts(CSP csp, HttpMessage msg, Source source) {
        // Start with the script tags
        List<Element> scripts = source.getAllElements("script");
        LOGGER.debug("Got scripts " + scripts.size());
        for (Element script : scripts) {
            String src = script.getAttributeValue("src");
            if (src != null) {
                LOGGER.debug("Adding url " + src);
                csp.getScriptSource().addUrl(src);
            } else {
                // Handle inline scripts
                String content = script.getContent().toString();
                csp.getScriptSource().addHashNonce("'" + ExtensionCspHelper.sha256(content) + "'");
                LOGGER.debug(
                        "Adding hash "
                                + ExtensionCspHelper.sha256(
                                        script.getContent().toString())); // TODO
                handleWorkerSources(content, csp);
                handleConnectSources(content, csp);
            }
        }
        LOGGER.debug("Csp now " + csp.getSite() + " : " + csp.generate()); // TODO
    }

    private void handleWorkerSources(String content, CSP csp) {
        // Regex checks to identify connect-src, worker-src etc
        ArrayList<String> workers =
                regexGetGroup("(Worker|\\.register)\\([\"']([\\w\\.:/?=&]*)[\"']", 2, content);
        for (String w : workers) {
            csp.getWorkerSource().addUrl(w);
        }
    }

    private void handleConnectSources(String content, CSP csp) {
        // Regex checks to identify connect-src
        // (WebSocket|EventSource|\\.sendBeacon)\\([\"']([\\w\\.:/?=&#]*)[\"']
        // \\.open\\([\"'][a-zA-Z]+[\"'],\\s*[\"']([\\w\\.:/?=&#]*)[\"']
        ArrayList<String> connects =
                regexGetGroup("[\"']((http[s]?:\\/\\/)?\\w+\\.\\w[\\.\\w/?=&]+)[\"']", 1, content);
        for (String c : connects) {
            switch (getLinkType(c)) {
                case LINK_TYPE_IMAGE:
                    csp.getImageSource().addUrl(c);
                    break;
                case LINK_TYPE_STYLE:
                    csp.getStyleSource().addUrl(c);
                    break;
                case LINK_TYPE_SCRIPT:
                    csp.getScriptSource().addUrl(c);
                    break;
                case LINK_TYPE_REQUEST:
                    csp.getConnectSource().addUrl(c);
                    break;
                default:
                    break;
            }
        }
    }

    private void handleImages(CSP csp, HttpMessage msg, Source source) {
        // Images tags
        List<Element> images = source.getAllElements("img");
        for (Element image : images) {
            String src = image.getAttributeValue("src");
            if (src != null) {
                csp.getImageSource().addUrl(src);
            }
        }
    }

    private void handleMedia(CSP csp, HttpMessage msg, Source source) {
        // Media (audio/video) tags
        String[] mediaTypes = new String[] {"audio", "video"};
        for (String mediaType : mediaTypes) {
            List<Element> media = source.getAllElements(mediaType);
            for (Element m : media) {
                List<Element> inner = m.getChildElements();
                for (Element childEl : inner) {
                    String src = childEl.getAttributeValue("src");
                    if (src != null) {
                        csp.getMediaSource().addUrl(src);
                    }
                }
            }
        }
    }

    private void handleFrames(CSP csp, HttpMessage msg, Source source) {
        // Frameset tags
        List<Element> framesets = source.getAllElements("frameset");
        for (Element frame : framesets) {
            List<Element> inner = frame.getChildElements();
            for (Element childEl : inner) {
                String src = childEl.getAttributeValue("src");
                if (src != null) {
                    // Set old-school deprecated frame-src due to WebKit only supporting CSP1
                    // (https://scotthelme.co.uk/csp-cheat-sheet/#frame-src)
                    csp.getFrameSource().addUrl(src);
                    // And new standard, child-src
                    csp.getChildSource().addUrl(src);
                }
            }
        }
        // Iframe tags
        List<Element> iframes = source.getAllElements("iframe");
        for (Element iframe : iframes) {
            String src = iframe.getAttributeValue("src");
            if (src != null) {
                // Set old-school deprecated frame-src due to WebKit only supporting CSP1
                // (https://scotthelme.co.uk/csp-cheat-sheet/#frame-src)
                csp.getFrameSource().addUrl(src);
                // And new standard, child-src
                csp.getChildSource().addUrl(src);
            }
        }
    }

    private void handleObjects(CSP csp, HttpMessage msg, Source source) {
        // Object tags
        List<Element> objects = source.getAllElements("object");
        for (Element object : objects) {
            String archive = object.getAttributeValue("archive");
            String codebase = object.getAttributeValue("codebase");
            String data = object.getAttributeValue("archive");
            String type = object.getAttributeValue("type");
            if (data != null) {
                csp.getObjectSource().addUrl(data);
            }
            if (codebase != null) {
                csp.getObjectSource().addUrl(codebase);
            }
            if (archive != null) {
                String[] archives = archive.split(" ");
                for (String a : archives) {
                    csp.getObjectSource().addUrl(a);
                }
            }
            // type attr for plugin-types
            if (type != null) {
                csp.getPluginTypes().addExtra(type);
            }
        }
        // Embed tags
        List<Element> embeds = source.getAllElements("embed");
        for (Element embed : embeds) {
            String src = embed.getAttributeValue("src");
            String pluginpage = embed.getAttributeValue("pluginspage");
            if (src != null) {
                csp.getObjectSource().addUrl(src);
            }
            if (pluginpage != null) {
                csp.getObjectSource().addUrl(pluginpage);
            }
        }
    }

    private void handleFonts(CSP csp, HttpMessage msg, Source source) {
        // Fonts tags
        List<Element> fonts = source.getAllElements("font");
        for (Element font : fonts) {
            String src = font.getAttributeValue("src");
            if (src != null) {
                csp.getFontSource().addUrl(src);
            }
        }
    }

    private void handleForms(CSP csp, HttpMessage msg, Source source) {
        // Forms tags
        List<Element> forms = source.getAllElements("form");
        for (Element form : forms) {
            String action = form.getAttributeValue("action");
            if (action != null) {
                csp.getFormAction().addUrl(action);
            }
        }
    }

    private void handleLinks(CSP csp, HttpMessage msg, Source source) {
        // Link tags
        List<Element> links = source.getAllElements("link");
        for (Element link : links) {
            String rel = link.getAttributeValue("rel");
            String href = link.getAttributeValue("href");
            if (rel != null && href != null) {
                if (rel.equalsIgnoreCase("stylesheet")) {
                    csp.getStyleSource().addUrl(href);
                } else if (rel.equalsIgnoreCase("icon")) {
                    csp.getImageSource().addUrl(href);
                } else if (rel.equalsIgnoreCase("manifest")) {
                    csp.getManifestSource().addUrl(href);
                }
            }
        }
    }

    public ArrayList<String> regexGetGroup(String pat, int grp, String content) {
        Pattern pattern = Pattern.compile(pat);
        Matcher matcher = pattern.matcher(content);
        ArrayList<String> res = new ArrayList<String>();
        while (matcher.find()) {
            res.add(matcher.group(grp));
        }
        return res;
    }

    public void parse(HttpMessage msg) {

        String url = msg.getRequestHeader().getURI().toString();
        Source source = new Source(msg.getResponseBody().toString());
        CSP csp = this.ext.getCspForUrl(url);
        String content;
        if (csp != null && csp.isEnabled()) {
            // Content-Type header
            String contentType = msg.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
            if (contentType != null) {
                if (contentType.contains(";")) {
                    csp.getPluginTypes()
                            .addExtra(contentType.substring(0, contentType.indexOf(';')));
                } else {
                    csp.getPluginTypes().addExtra(contentType);
                }
            }
            if (msg.getResponseHeader().isHtml()) {
                String[] directives = csp.getDirectives();
                for (String directive : directives) {
                    parseDirective(csp, msg, source, directive);
                }
                // Process links (handles stylesheet links and icons)
                handleLinks(csp, msg, source);
                // Process JS event attributes
                // TODO: Not implemented in browsers yet
                // handleJsAttr(csp, source);
                LOGGER.debug("Got csp for " + csp.getSite() + " : " + csp.generate());
            } else if (msg.getResponseHeader().isJavaScript()) {
                content = msg.getResponseBody().toString();
                handleWorkerSources(content, csp);
                handleConnectSources(content, csp);
            } else if (contentType != null && contentType.toLowerCase().contains("text/css")) {
                content = msg.getResponseBody().toString();
                handleStyleLinks(content, csp);
            }
            if (!csp.isInitialised()) {
                // CSP object initialised
                csp.setInitialised(true);
            }
        }

        String referer = msg.getRequestHeader().getHeader(HttpHeader.REFERER);
        String contentType = msg.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
        if (referer != null && contentType != null) {
            CSP referrerCsp = this.ext.getCspForUrl(referer);
            if (referrerCsp != null && referrerCsp.isEnabled()) {
                LOGGER.debug("Found referer csp=" + referrerCsp.generate());
                if (contentType.contains(";")) {
                    referrerCsp
                            .getPluginTypes()
                            .addExtra(contentType.substring(0, contentType.indexOf(';')));
                } else {
                    referrerCsp.getPluginTypes().addExtra(contentType);
                }
                content = msg.getResponseBody().toString();
                if (msg.getResponseHeader().isJavaScript()) {
                    referrerCsp.getScriptSource().addUrl(url);
                    handleWorkerSources(content, referrerCsp);
                    handleConnectSources(content, referrerCsp);
                } else if (msg.getResponseHeader().isImage()) {
                    referrerCsp.getImageSource().addUrl(url);
                } else if (contentType.toLowerCase().contains("text/css")) {
                    referrerCsp.getStyleSource().addUrl(url);
                    handleStyleLinks(content, referrerCsp);
                } else if (contentType.toLowerCase().contains("/font-")) {
                    referrerCsp.getFontSource().addUrl(url);
                }
            }
        }
    }
}
