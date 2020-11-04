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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.CircularRedirectException;
import org.apache.commons.httpclient.URI;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.log4j.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.DocumentType;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.select.Elements;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

/**
 * a scan rule that looks for server side issues that could cause confusion as to the relative path
 * of the URL. On the client side, this can lead to the browser attempting to interpret HTML as CSS,
 * leading to XSS exploits, for instance
 *
 * @author 70pointer
 */
public class RelativePathConfusionScanRule extends AbstractAppPlugin {

    /** the logger object */
    private static Logger log = Logger.getLogger(RelativePathConfusionScanRule.class);

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanbeta.relativepathconfusion.";

    /**
     * a list of HTML attributes that load objects using a URL (and potentially using a relative
     * path), mapping to the HTML tags that use them
     */
    static final Map<String, String[]> RELATIVE_LOADING_ATTRIBUTE_TO_TAGS =
            new LinkedHashMap<String, String[]>();

    // statically populate the tag data
    static {
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put(
                "href",
                new String[] {
                    "link", "a", "area"
                }); // base has a href too, but it uses an absolute URL (or should do)
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put(
                "src",
                new String[] {
                    "img", "iframe", "frame", "embed", "script", "input", "audio", "video", "source"
                });
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put(
                "lowersrc",
                new String[] {
                    "img", "iframe", "frame", "embed", "script", "input", "audio", "video", "source"
                });
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put(
                "dynsrc",
                new String[] {
                    "img", "iframe", "frame", "embed", "script", "input", "audio", "video", "source"
                });
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put("action", new String[] {"form"});
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put("data", new String[] {"object"});
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put("codebase", new String[] {"applet", "object"});
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put(
                "cite", new String[] {"blockquote", "del", "ins", "q"});
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put("background", new String[] {"body"});
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put("longdesc", new String[] {"frame", "iframe", "img"});
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put("profile", new String[] {"head"});
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put("usemap", new String[] {"img", "input", "object"});
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put("classid", new String[] {"object"});
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put("formaction", new String[] {"button"});
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put("icon", new String[] {"command", "input"});
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put("manifest", new String[] {"html"});
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put("poster", new String[] {"video"});
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put("archive", new String[] {"object", "applet"});
        // The "style" tag is a bit different..
        // Example:	<div style="background: url(image.png)">
        // all except BASE, BASEFONT, HEAD, HTML, META, PARAM, SCRIPT, STYLE, TITLE can have the
        // "style" atribute
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put("style", new String[] {""});

        // we also look at the body (no attribute) of the style tag, since this can contain CSS like
        // "background-image: url(images/newsletter_headline1.gif);"
        RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.put("", new String[] {"style"});
    }

    /**
     * the public ids for doctypes that trigger quirks mode in various browsers.. see
     * https://hsivonen.fi/doctype/ for more details (NS6 ignored for the purposes of this exercise)
     */
    static final String[] DOCTYPE_PUBLIC_IDS_TRIGGERING_QUIRKS_MODE = {
        "-//W3C//DTD HTML 3.2 Final//EN" // on all browsers
        ,
        "-//W3C//DTD HTML 4.01//EN" // on MAC IE 5
        ,
        "-//W3C//DTD HTML 4.0 Transitional//EN" // on all browsers
        ,
        "-//W3C//DTD HTML 4.01 Transitional//EN" // on all browsers
        ,
        "-//W3C//DTD XHTML 1.0 Transitional//EN" // on Konq 3.2
        ,
        "-//W3C//DTD XHTML 1.1//EN" // on IE 6 & Opera 7.0, Konq 3.2
        ,
        "-//W3C//DTD XHTML Basic 1.0//EN" // on IE 6 & Opera 7.0, Konq 3.2
        ,
        "-//W3C//DTD XHTML 1.0 Strict//EN" // on IE 6 & Opera 7.0, Konq 3.2
        ,
        "ISO/IEC 15445:2000//DTD HTML//EN" // on most browsers
        ,
        "ISO/IEC 15445:2000//DTD HyperText Markup Language//EN" // on Kong 3.2
        ,
        "ISO/IEC 15445:1999//DTD HTML//EN" // on various browsers
        ,
        "ISO/IEC 15445:1999//DTD HyperText Markup Language//EN" // on Konq 3.2
    };

    //										     background: url(image.png)
    static final Pattern STYLE_URL_LOAD =
            Pattern.compile(
                    "[a-zA-Z_-]*\\s*:\\s*url\\s*\\([^/)]+[^)]*\\)",
                    Pattern.MULTILINE | Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

    // Note: important here to *NOT* include any characters that could cause the resulting file
    // suffix to be interpreted as a file with a file extension
    private static final char[] RANDOM_PARAMETER_CHARS =
            "abcdefghijklmnopqrstuvwyxz0123456789".toCharArray();

    /**
     * the attack path to be appended to the URL. This is static to avoid repeated attacks on the
     * same URL (in Attack mode, for instance) yielding new vulnerabilities via different random
     * file paths.
     */
    private static final String RANDOM_ATTACK_PATH =
            "/"
                    + RandomStringUtils.random(5, RANDOM_PARAMETER_CHARS)
                    + "/"
                    + RandomStringUtils.random(5, RANDOM_PARAMETER_CHARS);

    @Override
    public int getId() {
        return 10051;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.SERVER;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public void scan() {

        // get the base message. What else did you think this line of code might do??
        HttpMessage originalMsg = getBaseMsg();

        if (log.isDebugEnabled()) {
            log.debug("Attacking at Attack Strength: " + this.getAttackStrength());
            log.debug(
                    "Checking ["
                            + originalMsg.getRequestHeader().getMethod()
                            + "] ["
                            + originalMsg.getRequestHeader().getURI()
                            + "], for Relative Path Confusion issues");
        }

        try {
            URI baseUri = originalMsg.getRequestHeader().getURI();
            String filename = baseUri.getName();
            String fileext = "";

            // is there a file extension at the end of the file name?
            if (filename != null && filename.length() > 0) {
                fileext = FilenameUtils.getExtension(filename);
            }

            // only filenames that have a file extension are potentially vulnerable to Relative Path
            // Confusion
            // (based on the instances of this that I've in seen in the wild, at least)
            if (fileext != null && fileext.length() > 0) {
                if (log.isDebugEnabled())
                    log.debug("The file extension of " + baseUri.getURI() + " is " + fileext);

                // 1: First manipulate the URL, using a URL which is ambiguous..
                URI originalURI = originalMsg.getRequestHeader().getURI();
                String path = originalURI.getPath();
                if (path == null) path = "";
                String query = originalURI.getQuery();
                if (query == null) query = "";

                URI hackedUri =
                        new URI(
                                originalURI.getScheme(),
                                originalURI.getAuthority(),
                                path + RANDOM_ATTACK_PATH + "?" + query,
                                null,
                                null);
                HttpMessage hackedMessage = new HttpMessage(hackedUri);
                try {
                    hackedMessage.setCookieParams(originalMsg.getCookieParams());
                } catch (Exception e) {
                    log.warn("Could not set the cookies from the base request:" + e);
                }
                try {
                    sendAndReceive(hackedMessage, true); // follow redirects
                } catch (CircularRedirectException e) {
                    log.warn("Ignoring a CircularRedirectException" + e);
                }

                // get ready to parse the HTML
                Document doc = Jsoup.parse(new String(hackedMessage.getResponseBody().getBytes()));
                String extraInfo = null;

                // 2: check if the response has a "<base>" tag specifying the base location for any
                // relative URLs
                // there can be a max of 1 <base> element in a document, and it must be inside the
                // <head> element
                // Example: <head><base href="http://www.w3schools.com/images/"
                // target="_blank"></head>
                Elements baseHrefInstances = doc.select("html > head > base[href]");
                if (!baseHrefInstances.isEmpty() && baseHrefInstances.size() == 1) {
                    // a single base was specified, in line with HTTP spec
                    if (log.isDebugEnabled())
                        log.debug(
                                "A base was specified, so there should be no confusion over relative paths (unless the User Agent is completely broken)");
                    return;
                } else {
                    if (!baseHrefInstances.isEmpty() && baseHrefInstances.size() > 1) {
                        extraInfo =
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "extrainfo.morethanonebasetag");
                        if (log.isDebugEnabled())
                            log.debug(
                                    "There more than one base (which is not valid HTML) specified for the page");
                    } else {
                        if (extraInfo == null)
                            extraInfo =
                                    Constant.messages.getString(
                                            MESSAGE_PREFIX + "extrainfo.nobasetag");
                        if (log.isDebugEnabled())
                            log.debug("There is no base specified for the page");
                    }
                }

                // 3: check if there are any resources that are loaded using relative URLs in the
                // response. (images, CSS, etc.)
                boolean relativeReferenceFound = false;
                String relativeReferenceEvidence = "";

                Set<String> loadingHtmlAttributes = RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.keySet();
                Iterator<String> i = loadingHtmlAttributes.iterator();
                for (; i.hasNext() && !relativeReferenceFound; ) {
                    String loadingHtmlAttribute = i.next();
                    String[] loadingHtmlTags =
                            RELATIVE_LOADING_ATTRIBUTE_TO_TAGS.get(loadingHtmlAttribute);

                    for (int tagIndex = 0;
                            tagIndex < loadingHtmlTags.length && !relativeReferenceFound;
                            tagIndex++) {
                        String tag = loadingHtmlTags[tagIndex];

                        // get instances of the specified HTML attribute and tag from the original
                        // response
                        // and see if is loading a relative URL.
                        // (ie, could it be confused if the server side can confuse the client side
                        // as to the absolute path to use when loading)
                        String selectStatement =
                                (tag.equals("") ? "" : tag)
                                        + (loadingHtmlAttribute.equals("")
                                                ? ""
                                                : "[" + loadingHtmlAttribute + "]");
                        Elements loadingTagInstances = doc.select(selectStatement);
                        int size = loadingTagInstances.size();

                        for (int index = 0; index < size && !relativeReferenceFound; index++) {
                            Element tagInstance = loadingTagInstances.get(index);

                            // handle style tags differently to other tags (for which we look at an
                            // attribute)
                            if (tag.toUpperCase().equals("STYLE")) {
                                // for the style tag, look at the entire body, not an attribute..
                                String styleBody = tagInstance.data();
                                if (log.isDebugEnabled())
                                    log.debug("Got <style> data: " + styleBody);
                                Matcher matcher = STYLE_URL_LOAD.matcher(styleBody);
                                if (matcher.find()) {
                                    relativeReferenceFound = true;
                                    relativeReferenceEvidence = matcher.group();
                                    if (log.isDebugEnabled())
                                        log.debug(
                                                "Got relative STYLE reference in a style tag. Evidence: "
                                                        + relativeReferenceEvidence);
                                }
                            } else {
                                // it's not the style tag, so look at the named attribute.
                                String attributeValue = tagInstance.attr(loadingHtmlAttribute);

                                if (log.isDebugEnabled())
                                    log.debug(
                                            "Got "
                                                    + attributeValue
                                                    + " for statement "
                                                    + selectStatement);

                                // is it a relative reference?
                                String attributeUpper = attributeValue.toUpperCase().trim();
                                // if the reference starts with a scheme, it's absolute
                                // if it starts with "/", it's probably an absolute path (the host
                                // and scheme are inferred)
                                // if it starts with "//, it's a reference to the host and path (but
                                // not the scheme), and it's essentially an absolute reference..
                                // if it starts with or is simply "#" it is either a fragment link
                                // or JS invocation
                                if (!loadingHtmlAttribute.equals("style")) {
                                    if (!attributeUpper.startsWith("HTTP://")
                                            && !attributeUpper.startsWith("HTTPS://")
                                            && !attributeUpper.startsWith("/")
                                            && !attributeUpper.startsWith("#")) {
                                        // it's a relative reference..
                                        relativeReferenceFound = true;
                                        // Note: since we parsed the HTML, and are reconstructing
                                        // the tag, this value may not exactly mirror the original
                                        // value in the HTML, but it's better than nothing. Whatcha
                                        // gonna do?
                                        // relativeReferenceEvidence = "<"+ tag + " " +
                                        // loadingHtmlAttribute + "=\"" + attributeValue + "\"";
                                        relativeReferenceEvidence = tagInstance.outerHtml();

                                        if (log.isDebugEnabled())
                                            log.debug(
                                                    "Got relative reference: "
                                                            + attributeValue
                                                            + " for statement "
                                                            + selectStatement
                                                            + ". Evidence: "
                                                            + relativeReferenceEvidence);
                                    }
                                } else {
                                    // for the style attribute (on various tags), look for a pattern
                                    // like "background: url(image.png)"
                                    Matcher matcher = STYLE_URL_LOAD.matcher(attributeUpper);
                                    if (matcher.find()) {
                                        relativeReferenceFound = true;
                                        relativeReferenceEvidence =
                                                attributeValue; // matcher.group();
                                        if (log.isDebugEnabled())
                                            log.debug(
                                                    "Got relative STYLE reference: "
                                                            + attributeValue
                                                            + " for "
                                                            + tag
                                                            + "."
                                                            + loadingHtmlAttribute
                                                            + ". Evidence: "
                                                            + relativeReferenceEvidence);
                                    }
                                }
                            }
                        }
                    }
                }
                // TODO: what if the relative reference is occurring in the JavaScript??
                // if there are no relative references in the response, bale out, because there is
                // nothing to worry about
                if (!relativeReferenceFound) {
                    if (log.isDebugEnabled())
                        log.debug(
                                "No relative references were found in the original response, so there is no possibility for confusion over relative path references)");
                    return;
                }

                // 4: Now check the content type of the response.
                // If no Content Type was specified, happy days, we can move to the next check in
                // the knowledge that the content can
                // be interpreted a non-HTML content type by the web browser, if we can fool the
                // browser into loading the page.
                // If a content type is "Content-Type: text/html", we need to see if there is a way
                // to override the Content Type.
                // Known ways are:
                // a: Get the browser to render in Quirks Mode
                //		Note 1: Quirks mode might have been set in the response, without us having to do
                // anything else.. check!
                //		Note 2: Quirks mode is set if the response does not set a doctype, or uses an
                // old doctype
                //		Note 3: If quirks mode is not enabled, we may be able to enable it by setting it
                // on a framing page (if the page in question allows framing)
                //
                // TODO: Pass in a random filename (something like the
                // aaa/bbb/blah.php/xxx/yyy/zzz?a=1&b=2 request we use here)
                //       that ends in ".css", to see if the web server changes the content type to
                // "text/css" (unlikely!)
                String contentType =
                        hackedMessage.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
                if (contentType != null) {

                    if (log.isDebugEnabled())
                        log.debug(
                                "Content Type is set, so we need to see if there is a way to bypass it");
                    boolean quirksMode = false;
                    if (extraInfo == null)
                        extraInfo =
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "extrainfo.contenttypeenabled",
                                        contentType);
                    else
                        extraInfo +=
                                "\n"
                                        + Constant.messages.getString(
                                                MESSAGE_PREFIX + "extrainfo.contenttypeenabled",
                                                contentType);

                    // a: Quirks mode!
                    // Is it already enabled?
                    // In the HEAD.. (Note: X-UA-Compatible trumps the doctype in IE)
                    // <meta http-equiv="X-UA-Compatible" content="IE=EmulateIE7">
                    // <meta http-equiv="X-UA-Compatible" content="IE=8" />
                    // <meta http-equiv="x-ua-compatible" content="IE=9">
                    // <meta http-equiv="x-ua-compatible" content="IE=edge" >   sets the page to
                    // HTML5 mode, not quirks mode!!!

                    // HTML 5: <!doctype html>									sets the page to HTML5 mode

                    Elements httpEquivInstances = doc.select("html > head > meta[http-equiv]");
                    int size = httpEquivInstances.size();

                    for (int index = 0; index < size; index++) {
                        Element e = httpEquivInstances.get(index);
                        String httpEquivAttributeValue = e.attr("http-equiv");
                        String contentAttributeValue = e.attr("content");

                        if (log.isDebugEnabled())
                            log.debug(
                                    "Got "
                                            + httpEquivAttributeValue
                                            + " for html > head > meta[http-equiv]");
                        if (httpEquivAttributeValue.toUpperCase().trim().equals("X-UA-COMPATIBLE")
                                && !contentAttributeValue.toUpperCase().trim().equals("IE=EDGE")) {
                            // Quirks mode is already enabled!
                            // Note: if this is present, it overrides any "<!doctype html>" that
                            // would otherwise set the page to HTML5 mode
                            quirksMode = true;
                            if (log.isDebugEnabled())
                                log.debug(
                                        "Quirks mode is explicitly enabled via <meta http-equiv=\"x-ua-compatible\" (which overrides any \"<!doctype html>\" HTML 5 directive) ... This allows the specified Content Type to be bypassed");
                            if (extraInfo == null)
                                extraInfo =
                                        Constant.messages.getString(
                                                MESSAGE_PREFIX
                                                        + "extrainfo.quirksmodeenabledexplicitly",
                                                httpEquivAttributeValue);
                            else
                                extraInfo +=
                                        "\n"
                                                + Constant.messages.getString(
                                                        MESSAGE_PREFIX
                                                                + "extrainfo.quirksmodeenabledexplicitly",
                                                        httpEquivAttributeValue);
                        }
                    }
                    // is quirks mode implicitly enabled via the absence of a doctype?
                    // is quirks mode implicitly enabled via an old doctype?
                    if (!quirksMode) {
                        boolean docTypeSpecified = false;
                        List<Node> nodes = doc.childNodes();
                        for (Node node : nodes) {
                            if (node instanceof DocumentType) {
                                docTypeSpecified = true;
                                DocumentType documentType = (DocumentType) node;
                                String docTypePublicId = documentType.attr("publicid");
                                // is the doctype old enough to enable quirks mode?
                                for (String doctypePublicIdTiggerQuirks :
                                        DOCTYPE_PUBLIC_IDS_TRIGGERING_QUIRKS_MODE) {
                                    if (docTypePublicId
                                            .toUpperCase()
                                            .equals(doctypePublicIdTiggerQuirks.toUpperCase())) {
                                        // this doctype is know to trigger quirks mode in some
                                        // browsers..
                                        quirksMode = true;
                                        if (log.isDebugEnabled())
                                            log.debug(
                                                    "Quirks mode is implicitly triggered via the use of old doctype "
                                                            + docTypePublicId
                                                            + ". This allows the specified Content Type to be bypassed");
                                        if (extraInfo == null)
                                            extraInfo =
                                                    Constant.messages.getString(
                                                            MESSAGE_PREFIX
                                                                    + "extrainfo.quirksmodeenabledimplicitly",
                                                            docTypePublicId);
                                        else
                                            extraInfo +=
                                                    "\n"
                                                            + Constant.messages.getString(
                                                                    MESSAGE_PREFIX
                                                                            + "extrainfo.quirksmodeenabledimplicitly",
                                                                    docTypePublicId);
                                        break;
                                    }
                                }
                                if (log.isDebugEnabled())
                                    log.debug(
                                            "DocType public id: "
                                                    + docTypePublicId
                                                    + ". Entire thing: "
                                                    + documentType);
                            }
                        }
                        if (!docTypeSpecified) {
                            quirksMode = true;
                            if (log.isDebugEnabled())
                                log.debug(
                                        "Quirks mode is implicitly enabled via the absence of a doctype... This allows the specified Content Type to be bypassed");
                            if (extraInfo == null)
                                extraInfo =
                                        Constant.messages.getString(
                                                MESSAGE_PREFIX
                                                        + "extrainfo.quirksmodeenabledimplicitlynodoctype");
                            else
                                extraInfo +=
                                        "\n"
                                                + Constant.messages.getString(
                                                        MESSAGE_PREFIX
                                                                + "extrainfo.quirksmodeenabledimplicitlynodoctype");
                        }
                    }

                    // if quirksMode is enabled, we do not need to check to see if framing attacks
                    // are feasible
                    boolean framingAttackPossible = false;
                    if (!quirksMode) {
                        // if the framing attack does not work, check for a framing attack
                        String frameHeader =
                                hackedMessage
                                        .getResponseHeader()
                                        .getHeader(HttpHeader.X_FRAME_OPTION);
                        if (frameHeader != null) {
                            if (frameHeader.toUpperCase().equals("DENY")) {
                                // definitely rules out the framing attack (unless the user is using
                                // a dozy web browser that doesn't understand "X-FRAME-OPTIONS:
                                // DENY")
                                framingAttackPossible = false;
                                if (log.isDebugEnabled())
                                    log.debug(
                                            "\"X-FRAME-OPTIONS: DENY\" rules out a framing attack, unless a really old browser is used (IE < 8.0, for instance)");
                            } else if (frameHeader.toUpperCase().equals("SAMEORIGIN")) {
                                // let's say this rules it out (unless the attacker has a persistent
                                // XSS, or already owns the site)
                                framingAttackPossible = false;
                                if (log.isDebugEnabled())
                                    log.debug(
                                            "\"X-FRAME-OPTIONS: SAMEORIGIN\" rules out a framing attack, unless a really old browser is used (IE < 8.0, for instance)");
                            } else if (frameHeader.toUpperCase().startsWith("ALLOW-FROM")) {
                                // let's say this rules it out (unless the attacker has a persistent
                                // XSS, or already owns the site)
                                framingAttackPossible = false;
                                if (log.isDebugEnabled())
                                    log.debug(
                                            "\"X-FRAME-OPTIONS: ALLOW-FROM\" probably rules out a framing attack, unless the attacker owns the website in the ALLOW-FROM, which is generally very unlikely");
                            }
                        } else {
                            // no framing headers were specified, so a framing attack is possible to
                            // force quicks mode, to bypass the Content-Type, which was specified
                            framingAttackPossible = true;
                            if (extraInfo == null)
                                extraInfo =
                                        Constant.messages.getString(
                                                MESSAGE_PREFIX + "extrainfo.framingallowed");
                            else
                                extraInfo +=
                                        "\n"
                                                + Constant.messages.getString(
                                                        MESSAGE_PREFIX
                                                                + "extrainfo.framingallowed");
                        }
                    }

                    // if quirks mode is off, and a framing attack is not possible, we can't "break
                    // out" of the content type.. boo hoo..
                    if ((!quirksMode) && (!framingAttackPossible)) {
                        if (log.isDebugEnabled())
                            log.debug(
                                    "Can't see a way to break out of the Content-Type, since Quirks mode is off (both explicit and implicit), and the page cannot be framed.");
                        return;
                    }
                } else {
                    // happy days. Content type is not set, so no hacks required to bypass it.
                    if (log.isDebugEnabled())
                        log.debug(
                                "Content Type is not set, so no hacks are required to bypass it!");
                    if (extraInfo == null)
                        extraInfo =
                                Constant.messages.getString(
                                        MESSAGE_PREFIX + "extrainfo.nocontenttype");
                    else
                        extraInfo +=
                                "\n"
                                        + Constant.messages.getString(
                                                MESSAGE_PREFIX + "extrainfo.nocontenttype");
                }

                // alert it..
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setUri(getBaseMsg().getRequestHeader().getURI().getURI())
                        .setAttack(hackedUri.getURI())
                        .setOtherInfo(extraInfo)
                        .setEvidence(relativeReferenceEvidence)
                        .setMessage(hackedMessage)
                        .raise();

                if (log.isDebugEnabled()) {
                    log.debug(
                            "A Relative Path Confusion issue exists on "
                                    + getBaseMsg().getRequestHeader().getURI().getURI());
                }
                return;

            } else {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "The URI has no filename component, so there is unlikely to be any ambiguity over any relative paths");
                }
            }
        } catch (Exception e) {
            log.error("Error scanning a request for Relative Path confusion: " + e.getMessage(), e);
        }
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM; // Medium or High? We'll see what the community consensus is..
    }

    @Override
    public int getCweId() {
        return 20; // Improper Input Validation
    }

    @Override
    public int getWascId() {
        return 20; // Improper Input Handling
    }
}
