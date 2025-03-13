/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.exim.sites;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HtmlParameter.Type;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.exim.ExporterResult;
import org.zaproxy.addon.exim.ExtensionExim;
import org.zaproxy.zap.model.NameValuePair;
import org.zaproxy.zap.utils.Stats;

public class SitesTreeHandler {

    private static final Logger LOGGER = LogManager.getLogger(SitesTreeHandler.class);

    private static final ObjectMapper YAML_MAPPER;
    private static final Yaml YAML_PARSER;

    static {
        // Configure YAML mapper with appropriate settings
        YAML_MAPPER =
                new ObjectMapper(
                        new YAMLFactory()
                                .disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER)
                                .enable(YAMLGenerator.Feature.MINIMIZE_QUOTES)
                                .enable(YAMLGenerator.Feature.LITERAL_BLOCK_STYLE)
                                .configure(YAMLGenerator.Feature.SPLIT_LINES, false)
                                .configure(
                                        YAMLGenerator.Feature.ALWAYS_QUOTE_NUMBERS_AS_STRINGS,
                                        false));

        YAML_MAPPER.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        YAML_MAPPER.configure(SerializationFeature.INDENT_OUTPUT, true);

        // Use snake yaml only for parsing
        YAML_PARSER = new Yaml(new LoaderOptions());
    }

    public static void exportSitesTree(File file, ExporterResult result) throws IOException {
        try (FileWriter fw = new FileWriter(file, false)) {
            exportSitesTree(fw, result);
        }
    }

    public static void exportSitesTree(Writer fw, ExporterResult result) throws IOException {
        exportSitesTree(fw, Model.getSingleton().getSession().getSiteTree(), result);
    }

    public static void exportSitesTree(Writer fw, SiteMap sites, ExporterResult result)
            throws IOException {
        try (BufferedWriter bw = new BufferedWriter(fw)) {
            outputNode(bw, sites.getRoot(), 0, result);
        }
    }

    private static void outputKV(
            BufferedWriter fw, String indent, boolean first, String key, Object value)
            throws IOException {
        fw.write(indent);
        if (first) {
            fw.write("- ");
        } else {
            fw.write("  ");
        }
        fw.write(key);
        fw.write(": ");

        // Let Jackson handle the YAML formatting
        if (value == null) {
            fw.write("null");
            fw.newLine();
            return;
        }

        String yamlValue = YAML_MAPPER.writeValueAsString(value).trim();

        // For simple single-line values
        if (!yamlValue.contains("\n")) {
            fw.write(yamlValue);
            fw.newLine(); // Add consistent newline
        } else {
            // For multi-line values, handle indentation
            fw.newLine(); // Start value on next line
            String extraIndent = indent + (first ? "- " : "  ").replaceAll("\\.", " ") + "  ";
            String[] lines = yamlValue.split("\n");
            for (String line : lines) {
                fw.write(extraIndent);
                fw.write(line);
                fw.newLine();
            }
        }
    }

    private static void outputNode(
            BufferedWriter fw, SiteNode node, int level, ExporterResult result) throws IOException {
        // We could create a set of data structures and use snakeyaml, but the format is
        // very simple
        // and this is much more memory efficient - it still uses snakeyaml for encoding
        String indent = " ".repeat(level * 2);
        HistoryReference href = node.getHistoryReference();

        outputKV(
                fw,
                indent,
                true,
                EximSiteNode.NODE_KEY,
                level == 0 ? EximSiteNode.ROOT_NODE_NAME : node.toString());

        if (href != null) {
            outputKV(fw, indent, false, EximSiteNode.URL_KEY, href.getURI().toString());
            outputKV(fw, indent, false, EximSiteNode.METHOD_KEY, href.getMethod());

            if (href.getStatusCode() > 0) {
                outputKV(
                        fw,
                        indent,
                        false,
                        EximSiteNode.RESPONSE_LENGTH_KEY,
                        href.getResponseHeaderLength() + href.getResponseBodyLength() + 2);
                outputKV(fw, indent, false, EximSiteNode.STATUS_CODE_KEY, href.getStatusCode());
            }

            if (HttpRequestHeader.POST.equals(href.getMethod())) {
                try {
                    HttpMessage msg = href.getHttpMessage();
                    String contentType = msg.getRequestHeader().getHeader(HttpHeader.CONTENT_TYPE);
                    if (contentType == null
                            || !contentType.startsWith(HttpHeader.FORM_MULTIPART_CONTENT_TYPE)) {
                        List<NameValuePair> params =
                                Model.getSingleton().getSession().getParameters(msg, Type.form);
                        StringBuilder sb = new StringBuilder();
                        params.forEach(
                                nvp -> {
                                    if (sb.length() > 0) {
                                        sb.append('&');
                                    }
                                    sb.append(nvp.getName());
                                    sb.append("=");
                                });
                        outputKV(fw, indent, false, EximSiteNode.DATA_KEY, sb.toString());
                    }
                } catch (IOException | DatabaseException e) {
                    LOGGER.error(e.getMessage(), e);
                }
            }
        }
        result.incrementCount();
        Stats.incCounter(ExtensionExim.STATS_PREFIX + "save.sites.node");

        if (node.getChildCount() > 0) {
            fw.write(indent);
            fw.write("  ");
            fw.write(EximSiteNode.CHILDREN_KEY);
            fw.write(": ");
            fw.newLine();
            node.children()
                    .asIterator()
                    .forEachRemaining(
                            c -> {
                                try {
                                    outputNode(fw, (SiteNode) c, level + 1, result);
                                } catch (IOException e) {
                                    LOGGER.error(e.getMessage(), e);
                                }
                            });
        }
    }

    public static void pruneSiteNodes(EximSiteNode node, PruneSiteResult result, SiteMap siteMap) {
        // Delete children first
        if (!EximSiteNode.ROOT_NODE_NAME.equals(node.getNode())) {
            result.incReadNodes();
        }
        node.getChildren().forEach(child -> pruneSiteNodes(child, result, siteMap));

        try {
            if (node.getUrl() != null) {
                URI uri = new URI(node.getUrl(), true);
                SiteNode sn;
                if (node.getNode().contains("(" + HttpHeader.FORM_MULTIPART_CONTENT_TYPE + ")")) {
                    // Indicates this request used a multipart form POST
                    HttpMessage msg = new HttpMessage(uri);
                    msg.getRequestHeader().setMethod(node.getMethod());
                    msg.getRequestHeader()
                            .setHeader(
                                    HttpHeader.CONTENT_TYPE,
                                    HttpHeader.FORM_MULTIPART_CONTENT_TYPE);
                    sn = siteMap.findNode(msg);
                } else {
                    sn = siteMap.findNode(uri, node.getMethod(), node.getData());
                }
                if (sn != null && sn.getChildCount() == 0) {
                    siteMap.removeNodeFromParent(sn);
                    result.incDeletedNodes();
                    LOGGER.debug("Deleted node {}", sn.getHierarchicNodeName());
                } else if (sn == null) {
                    // findNode typically does not find non leaf nodes, even those which no longer
                    // have any children
                    sn = siteMap.findClosestParent(new URI(node.getUrl() + "/test", true));
                    if (sn != null && sn.getChildCount() == 0) {
                        siteMap.removeNodeFromParent(sn);
                        result.incDeletedNodes();
                    }
                } else {
                    LOGGER.debug(
                            "Keeping node {} as it has {} children",
                            sn.getHierarchicNodeName(),
                            sn.getChildCount());
                }
            }
        } catch (NullPointerException | URIException | HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    public static PruneSiteResult pruneSiteNodes(File file) {
        try (FileInputStream is = new FileInputStream(file)) {
            return pruneSiteNodes(is, Model.getSingleton().getSession().getSiteTree());
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            PruneSiteResult res = new PruneSiteResult();
            res.setError(
                    Constant.messages.getString(
                            "exim.sites.error.prune.exception", e.getMessage()));
            return res;
        }
    }

    protected static PruneSiteResult pruneSiteNodes(InputStream is, SiteMap siteMap) {
        PruneSiteResult res = new PruneSiteResult();
        // Don't load yaml using the Constructor class - that throws exceptions that
        // don't give enough info
        Object obj = YAML_PARSER.load(is);
        if (obj instanceof ArrayList<?> list) {
            EximSiteNode rootNode = new EximSiteNode((LinkedHashMap<?, ?>) list.get(0));
            pruneSiteNodes(rootNode, res, siteMap);
        } else {
            LOGGER.error("Unexpected root node in yaml");
            res.setError(Constant.messages.getString("exim.sites.error.prune.badformat"));
        }
        return res;
    }
}
