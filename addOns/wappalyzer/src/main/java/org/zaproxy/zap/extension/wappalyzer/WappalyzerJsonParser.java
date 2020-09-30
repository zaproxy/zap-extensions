/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.wappalyzer;

import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.AffineTransform;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.PatternSyntaxException;
import javax.swing.ImageIcon;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.batik.anim.dom.SAXSVGDocumentFactory;
import org.apache.batik.bridge.BridgeContext;
import org.apache.batik.bridge.BridgeException;
import org.apache.batik.bridge.DocumentLoader;
import org.apache.batik.bridge.GVTBuilder;
import org.apache.batik.bridge.UserAgent;
import org.apache.batik.bridge.UserAgentAdapter;
import org.apache.batik.ext.awt.RenderingHintsKeyExt;
import org.apache.batik.gvt.GraphicsNode;
import org.apache.batik.util.XMLResourceDescriptor;
import org.apache.log4j.Logger;
import org.w3c.dom.svg.SVGDocument;

public class WappalyzerJsonParser {

    private static final String FIELD_CONFIDENCE = "confidence:";
    private static final String FIELD_VERSION = "version:";
    private static final int SIZE = 16;

    private static final Logger logger = Logger.getLogger(WappalyzerJsonParser.class);
    private final PatternErrorHandler patternErrorHandler;
    private final ParsingExceptionHandler parsingExceptionHandler;

    public WappalyzerJsonParser() {
        this(
                (pattern, e) -> logger.error("Invalid pattern syntax " + pattern, e),
                e -> logger.error(e.getMessage(), e));
    }

    WappalyzerJsonParser(PatternErrorHandler peh, ParsingExceptionHandler parsingExceptionHandler) {
        this.patternErrorHandler = peh;
        this.parsingExceptionHandler = parsingExceptionHandler;
    }

    public WappalyzerData parseDefaultAppsJson() throws IOException {
        return parseJson(getStringResource(ExtensionWappalyzer.RESOURCE + "/apps.json"));
    }

    WappalyzerData parseAppsJson(String path) {
        try {
            return parseJson(getStringResource(path));
        } catch (IOException e) {
            logger.warn("An error occurred reading the file: " + path);
        }
        return null;
    }

    private static String getStringResource(String resourceName) throws IOException {
        InputStream in = null;
        StringBuilder sb = new StringBuilder();
        try {
            in = ExtensionWappalyzer.class.getResourceAsStream(resourceName);
            int numRead = 0;
            byte[] buf = new byte[1024];
            while ((numRead = in.read(buf)) != -1) {
                sb.append(new String(buf, 0, numRead));
            }
            return sb.toString();

        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    // Ignore
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    public WappalyzerData parseJson(String jsonStr) {
        WappalyzerData result = new WappalyzerData();

        try {
            JSONObject json = JSONObject.fromObject(jsonStr);

            JSONObject cats = json.getJSONObject("categories");

            for (Object cat : cats.entrySet()) {
                Map.Entry<String, JSONObject> mCat = (Map.Entry<String, JSONObject>) cat;
                result.addCategory(mCat.getKey(), mCat.getValue().getString("name"));
            }

            JSONObject apps = json.getJSONObject("technologies");
            for (Object entry : apps.entrySet()) {
                Map.Entry<String, JSONObject> mApp = (Map.Entry<String, JSONObject>) entry;

                String appName = mApp.getKey();
                JSONObject appData = mApp.getValue();

                Application app = new Application();
                app.setName(appName);
                app.setDescription(appData.optString("description"));
                app.setWebsite(appData.getString("website"));
                app.setCategories(
                        this.jsonToCategoryList(result.getCategories(), appData.get("cats")));
                app.setHeaders(this.jsonToAppPatternMapList("HEADER", appData.get("headers")));
                app.setUrl(this.jsonToPatternList("URL", appData.get("url")));
                app.setHtml(this.jsonToPatternList("HTML", appData.get("html")));
                app.setScript(this.jsonToPatternList("SCRIPT", appData.get("scripts")));
                app.setMetas(this.jsonToAppPatternMapList("META", appData.get("meta")));
                app.setImplies(this.jsonToStringList(appData.get("implies")));
                app.setCpe(appData.optString("cpe"));

                URL iconUrl =
                        ExtensionWappalyzer.class.getResource(
                                ExtensionWappalyzer.RESOURCE + "/icons/" + appName + ".png");
                if (iconUrl != null) {
                    app.setIcon(createPngIcon(iconUrl));
                } else {
                    iconUrl =
                            ExtensionWappalyzer.class.getResource(
                                    ExtensionWappalyzer.RESOURCE + "/icons/" + appName + ".svg");
                    app.setIcon(createSvgIcon(iconUrl));
                }

                result.addApplication(app);
            }

        } catch (Exception e) {
            parsingExceptionHandler.handleException(e);
        }

        return result;
    }

    private static Graphics2D addRenderingHints(BufferedImage image) {
        Graphics2D g2d = image.createGraphics();
        g2d.setRenderingHint(
                RenderingHintsKeyExt.KEY_BUFFERED_IMAGE, new WeakReference<BufferedImage>(image));
        g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
        g2d.setRenderingHint(
                RenderingHints.KEY_ALPHA_INTERPOLATION,
                RenderingHints.VALUE_ALPHA_INTERPOLATION_QUALITY);
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_OFF);
        g2d.setRenderingHint(
                RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
        return g2d;
    }

    private static ImageIcon createPngIcon(URL url) throws Exception {
        ImageIcon appIcon = new ImageIcon(url);
        if (appIcon.getIconHeight() > SIZE || appIcon.getIconWidth() > SIZE) {
            BufferedImage image = new BufferedImage(SIZE, SIZE, BufferedImage.TYPE_INT_ARGB);
            Graphics2D g2d = addRenderingHints(image);
            g2d.drawImage(appIcon.getImage(), 0, 0, SIZE, SIZE, null);
            g2d.dispose();
            return new ImageIcon(image);
        }
        return appIcon;
    }

    private static ImageIcon createSvgIcon(URL url) throws Exception {
        if (url == null) {
            return null;
        }
        String xmlParser = XMLResourceDescriptor.getXMLParserClassName();
        SAXSVGDocumentFactory df = new SAXSVGDocumentFactory(xmlParser);
        SVGDocument doc = null;
        GraphicsNode svgIcon = null;
        try {
            doc = df.createSVGDocument(url.toString());
        } catch (RuntimeException re) {
            // v1 SVGs are unsupported
            return null;
        }
        doc.getRootElement().setAttribute("width", String.valueOf(SIZE));
        doc.getRootElement().setAttribute("height", String.valueOf(SIZE));
        UserAgent userAgent = new UserAgentAdapter();
        DocumentLoader loader = new DocumentLoader(userAgent);
        GVTBuilder builder = new GVTBuilder();
        try {
            svgIcon = builder.build(new BridgeContext(userAgent, loader), doc);
        } catch (BridgeException | StringIndexOutOfBoundsException ex) {
            logger.debug("Failed to parse SVG. " + ex.getMessage());
            return null;
        }

        AffineTransform transform = new AffineTransform(1, 0.0, 0.0, 1, 0, 0);
        BufferedImage image = new BufferedImage(SIZE, SIZE, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2d = addRenderingHints(image);
        svgIcon.setTransform(transform);
        svgIcon.paint(g2d);
        g2d.dispose();
        return new ImageIcon(image);
    }

    private List<String> jsonToStringList(Object json) {
        List<String> list = new ArrayList<String>();
        if (json instanceof JSONArray) {
            for (Object obj : (JSONArray) json) {
                list.add(obj.toString());
            }
        } else if (json != null) {
            list.add(json.toString());
        }
        return list;
    }

    private List<String> jsonToCategoryList(Map<String, String> categories, Object json) {
        List<String> list = new ArrayList<String>();
        if (json instanceof JSONArray) {
            for (Object obj : (JSONArray) json) {
                String category = categories.get(obj.toString());
                if (category != null) {
                    list.add(category);
                } else {
                    logger.error("Failed to find category for " + obj.toString());
                }
            }
        }
        return list;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, AppPattern>> jsonToAppPatternMapList(String type, Object json) {
        List<Map<String, AppPattern>> list = new ArrayList<Map<String, AppPattern>>();
        AppPattern ap;
        if (json instanceof JSONObject) {
            for (Object obj : ((JSONObject) json).entrySet()) {
                Map.Entry<String, String> entry = (Map.Entry<String, String>) obj;
                try {
                    Map<String, AppPattern> map = new HashMap<String, AppPattern>();
                    ap = this.strToAppPattern(type, entry.getValue());
                    map.put(entry.getKey(), ap);
                    list.add(map);
                } catch (NumberFormatException e) {
                    logger.error(
                            "Invalid field syntax " + entry.getKey() + " : " + entry.getValue(), e);
                } catch (PatternSyntaxException e) {
                    patternErrorHandler.handleError(entry.getValue(), e);
                }
            }
        } else if (json != null) {
            logger.error(
                    "Unexpected header type for "
                            + json.toString()
                            + " "
                            + json.getClass().getCanonicalName());
        }
        return list;
    }

    private List<AppPattern> jsonToPatternList(String type, Object json) {
        List<AppPattern> list = new ArrayList<AppPattern>();
        if (json instanceof JSONArray) {
            for (Object obj : ((JSONArray) json).toArray()) {
                String objStr = obj.toString();
                if (obj instanceof JSONArray) {
                    // Dereference it again
                    objStr = ((JSONArray) obj).getString(0);
                }
                try {
                    if (!objStr.isEmpty()) {
                        list.add(this.strToAppPattern(type, objStr));
                    }
                } catch (PatternSyntaxException e) {
                    patternErrorHandler.handleError(objStr, e);
                }
            }
        } else if (json != null) {
            try {
                String jsonValue = json.toString();
                if (!jsonValue.isEmpty()) {
                    list.add(this.strToAppPattern(type, jsonValue));
                }
            } catch (PatternSyntaxException e) {
                patternErrorHandler.handleError(json.toString(), e);
            }
        }
        return list;
    }

    private AppPattern strToAppPattern(String type, String str) {
        AppPattern ap = new AppPattern();
        ap.setType(type);
        String[] values = str.split("\\\\;");
        String pattern = values[0];
        for (int i = 1; i < values.length; i++) {
            try {
                if (values[i].startsWith(FIELD_CONFIDENCE)) {
                    ap.setConfidence(
                            parseConfidence(values[i].substring(FIELD_CONFIDENCE.length())));
                } else if (values[i].startsWith(FIELD_VERSION)) {
                    ap.setVersion(values[i].substring(FIELD_VERSION.length()));
                } else {
                    logger.error("Unexpected field: " + values[i]);
                }
            } catch (Exception e) {
                logger.error("Invalid field syntax " + values[i], e);
            }
        }
        if (pattern.indexOf(FIELD_CONFIDENCE) > 0) {
            logger.warn("Confidence field in pattern?: " + pattern);
        }
        if (pattern.indexOf(FIELD_VERSION) > 0) {
            logger.warn("Version field in pattern?: " + pattern);
        }
        ap.setPattern(pattern);
        return ap;
    }

    private int parseConfidence(String confidence) {
        if (confidence.contains(".")) {
            return (int) Double.parseDouble(confidence) * 100;
        }
        return Integer.parseInt(confidence);
    }

    interface ParsingExceptionHandler {
        void handleException(Exception e);
    }
}
