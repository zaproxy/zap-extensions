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
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import javax.swing.tree.TreeNode;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.VariantMultipartFormParameters;
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

    private static final String MULTIPART_ENTRY =
            "----boundary1234"
                    + HttpHeader.CRLF
                    + "Content-Disposition: form-data; name=\"%s\""
                    + HttpHeader.CRLF
                    + HttpHeader.CRLF
                    + ""
                    + HttpHeader.CRLF;

    private static final ObjectMapper YAML_MAPPER;
    private static final Yaml YAML_PARSER;

    static {
        YAML_MAPPER =
                YAMLMapper.builder()
                        .enable(YAMLGenerator.Feature.MINIMIZE_QUOTES)
                        .disable(YAMLGenerator.Feature.WRITE_DOC_START_MARKER)
                        .disable(YAMLGenerator.Feature.SPLIT_LINES)
                        .disable(YAMLGenerator.Feature.ALWAYS_QUOTE_NUMBERS_AS_STRINGS)
                        .defaultPropertyInclusion(
                                JsonInclude.Value.construct(
                                        JsonInclude.Include.NON_NULL, JsonInclude.Include.NON_NULL))
                        .enable(SerializationFeature.INDENT_OUTPUT)
                        .build();

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
            YAML_MAPPER
                    .copy()
                    .registerModule(
                            new SimpleModule()
                                    .addSerializer(SiteNode.class, new SiteNodeSerializer(result)))
                    .writeValue(bw, List.of(sites.getRoot()));
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
                if (node.getNode().contains("(multipart:")
                        && StringUtils.isNotBlank(node.getData())) {
                    // Indicates this request used a multipart form POST
                    HttpMessage msg = new HttpMessage(uri);
                    msg.getRequestHeader().setMethod(node.getMethod());
                    msg.getRequestHeader()
                            .setHeader(
                                    HttpHeader.CONTENT_TYPE,
                                    HttpHeader.FORM_MULTIPART_CONTENT_TYPE + "; boundary=----1234");
                    StringBuilder sb = new StringBuilder();
                    Arrays.stream(node.getData().split("&"))
                            .forEach(
                                    e ->
                                            sb.append(
                                                    MULTIPART_ENTRY.formatted(
                                                            URLDecoder.decode(
                                                                    e, StandardCharsets.UTF_8))));
                    sb.append(HttpHeader.CRLF).append("----boundary1234--").append(HttpHeader.CRLF);
                    msg.setRequestBody(sb.toString());
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
        Object obj = YAML_PARSER.load(is);
        if (obj instanceof ArrayList<?> list) {
            EximSiteNode rootNode = new EximSiteNode((LinkedHashMap<?, ?>) list.get(0));
            pruneSiteNodes(rootNode, res, siteMap);
        } else {
            LOGGER.warn("Unexpected root node in yaml");
            res.setError(Constant.messages.getString("exim.sites.error.prune.badformat"));
        }
        return res;
    }

    @SuppressWarnings("serial")
    private static class SiteNodeSerializer extends StdSerializer<SiteNode> {

        private static final long serialVersionUID = 1L;

        private ExporterResult result;

        public SiteNodeSerializer(ExporterResult result) {
            super(SiteNode.class);

            this.result = result;
        }

        @Override
        public void serialize(SiteNode value, JsonGenerator gen, SerializerProvider provider)
                throws IOException, JsonProcessingException {

            result.incrementCount();
            Stats.incCounter(ExtensionExim.STATS_PREFIX + "save.sites.node");

            gen.writeStartObject();
            gen.writeStringField(
                    EximSiteNode.NODE_KEY,
                    value.getParent() == null ? EximSiteNode.ROOT_NODE_NAME : value.toString());

            HistoryReference href = value.getHistoryReference();
            if (href != null) {

                gen.writeStringField(EximSiteNode.URL_KEY, href.getURI().toString());
                gen.writeStringField(EximSiteNode.METHOD_KEY, href.getMethod());

                if (href.getStatusCode() > 0) {
                    gen.writeNumberField(
                            EximSiteNode.RESPONSE_LENGTH_KEY,
                            href.getResponseHeaderLength() + href.getResponseBodyLength() + 2);
                    gen.writeNumberField(EximSiteNode.STATUS_CODE_KEY, href.getStatusCode());
                }

                if (HttpRequestHeader.POST.equals(href.getMethod())) {
                    try {
                        HttpMessage msg = href.getHttpMessage();
                        if (msg.getRequestHeader()
                                .hasContentType(HttpHeader.FORM_MULTIPART_CONTENT_TYPE)) {
                            VariantMultipartFormParameters mfp =
                                    new VariantMultipartFormParameters();
                            mfp.setMessage(msg);
                            StringBuilder sb = new StringBuilder();
                            mfp.getParamList().stream()
                                    .filter(p -> isRelevantMultipartParam(p.getType()))
                                    .map(org.parosproxy.paros.core.scanner.NameValuePair::getName)
                                    .forEach(
                                            e -> {
                                                if (sb.length() > 0) {
                                                    sb.append('&');
                                                }
                                                sb.append(
                                                        URLEncoder.encode(
                                                                e, StandardCharsets.UTF_8));
                                            });
                            gen.writeStringField(EximSiteNode.DATA_KEY, sb.toString());
                        } else {
                            List<NameValuePair> params =
                                    Model.getSingleton().getSession().getParameters(msg, Type.form);
                            StringBuilder sb = new StringBuilder();
                            params.forEach(
                                    nvp -> {
                                        if (sb.length() > 0) {
                                            sb.append('&');
                                        }
                                        sb.append(
                                                URLEncoder.encode(
                                                        nvp.getName(), StandardCharsets.UTF_8));
                                        sb.append("=");
                                    });
                            gen.writeStringField(EximSiteNode.DATA_KEY, sb.toString());
                        }
                    } catch (IOException | DatabaseException e) {
                        LOGGER.error(e.getMessage(), e);
                    }
                }
            }

            if (value.getChildCount() > 0) {
                gen.writeArrayFieldStart(EximSiteNode.CHILDREN_KEY);
                for (Enumeration<TreeNode> e = value.children(); e.hasMoreElements(); ) {
                    gen.writeObject(e.nextElement());
                }
                gen.writeEndArray();
            }
            gen.writeEndObject();
        }

        private static boolean isRelevantMultipartParam(int type) {
            return type
                            == org.parosproxy.paros.core.scanner.NameValuePair
                                    .TYPE_MULTIPART_DATA_FILE_NAME
                    || type
                            == org.parosproxy.paros.core.scanner.NameValuePair
                                    .TYPE_MULTIPART_DATA_PARAM;
        }
    }
}
