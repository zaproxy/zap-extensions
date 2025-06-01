/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.client.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator.Feature;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.zap.utils.Stats;

public final class ClientMapWriter {

    private static final String CHILDREN_KEY = "children";
    private static final String COMPONENTS_KEY = "components";
    private static final String FORM_ID_KEY = "formId";
    private static final String HREF_KEY = "href";
    private static final String ID_KEY = "id";
    private static final String NODE_TYPE_KEY = "nodeType";
    private static final String NODE_KEY = "node";
    private static final String ROOT_NODE_NAME = "ClientMap";
    private static final String STORAGE_EVENT_KEY = "storageEvent";
    private static final String STORAGE_KEY = "storage";
    private static final String TAG_NAME_KEY = "tagName";
    private static final String TAG_TYPE_KEY = "tagType";
    private static final String TEXT_KEY = "text";
    private static final String VISITED_KEY = "visited";

    private static final List<ClientSideComponent.Type> COMPONENT_TYPES_TO_SKIP =
            List.of(ClientSideComponent.Type.REDIRECT, ClientSideComponent.Type.CONTENT_LOADED);

    ClientMapWriter() {}

    public static void exportClientMap(Writer fw, ClientMap clientMap) throws IOException {
        try (BufferedWriter bw = new BufferedWriter(fw)) {
            outputNode(bw, clientMap.getRoot(), 0);
        }
    }

    private static boolean outputKV(
            Writer fw, String indent, boolean first, String key, Object value) throws IOException {
        if (value == null) {
            return first;
        }
        fw.write(indent);
        if (first) {
            fw.write("- ");
        } else {
            fw.write("  ");
        }
        fw.write(key);
        fw.write(": ");
        ObjectMapper mapper =
                new ObjectMapper(
                        new YAMLFactory()
                                .enable(Feature.LITERAL_BLOCK_STYLE)
                                .disable(Feature.WRITE_DOC_START_MARKER));
        // For some reason the disable start marker doesn't seem to work
        String output = mapper.writeValueAsString(value).replace("--- ", "");
        fw.write(output);
        return false;
    }

    private static void outputNode(Writer fw, ClientNode node, int level) throws IOException {
        if (node.isStorage()) {
            // Skip storage nodes in the tree
            // Those details are represented as components of their source
            return;
        }
        // We could create a set of data structures and use jackson, but the format is very
        // simple - it still uses jackson for value output
        String indent = " ".repeat(level * 2);

        outputKV(
                fw,
                indent,
                true,
                NODE_KEY,
                level == 0 ? ROOT_NODE_NAME : node.getUserObject().getName());

        if (node.getUserObject().isStorage()) {
            outputKV(fw, indent, false, STORAGE_KEY, node.getUserObject().isStorage());
        }
        if (!node.getUserObject().isVisited()) {
            outputKV(fw, indent, false, VISITED_KEY, node.getUserObject().isVisited());
        }
        if (node.getUserObject().getComponents() != null
                && !node.getUserObject().getComponents().isEmpty()) {
            for (ClientSideComponent component : node.getUserObject().getComponents()) {
                if (component.getType() == ClientSideComponent.Type.REDIRECT) {
                    outputKV(
                            fw, indent, false, component.getType().getLabel(), component.getHref());
                } else if (component.getType() == ClientSideComponent.Type.CONTENT_LOADED) {
                    outputKV(fw, indent, false, component.getType().getLabel(), true);
                }
            }
            synchronized (node.getUserObject().getComponents()) {
                indent = outputComponents(fw, node.getUserObject().getComponents(), level, indent);
            }
        }

        Stats.incCounter(ExtensionClientIntegration.PREFIX + ".export.clientmap.node");

        if (node.getChildCount() > 0) {
            fw.write(indent);
            fw.write("  ");
            fw.write(CHILDREN_KEY);
            fw.write(":");
            fw.write('\n');
            node.children()
                    .asIterator()
                    .forEachRemaining(
                            c -> {
                                try {
                                    outputNode(fw, (ClientNode) c, level + 1);
                                } catch (IOException e) {
                                    throw new UncheckedIOException(e);
                                }
                            });
        }
    }

    private static String outputComponents(
            Writer fw, Set<ClientSideComponent> components, int level, String indent)
            throws IOException {
        fw.write(indent);
        fw.write("  ");
        fw.write(COMPONENTS_KEY);
        fw.write(":\n");

        indent = " ".repeat((level + 1) * 2);

        SortedSet<ClientSideComponent> sortedComponents = new TreeSet<>(components);

        for (ClientSideComponent component : sortedComponents) {
            boolean first = true;
            if ((component.getType() != null
                    && COMPONENT_TYPES_TO_SKIP.contains(component.getType()))) {
                continue;
            }
            first = outputKV(fw, indent, first, NODE_TYPE_KEY, component.getType().getLabel());
            String href =
                    component.getHref() == null ? component.getParentUrl() : component.getHref();
            first = outputKV(fw, indent, first, HREF_KEY, href);
            if (!component.isStorageEvent()) {
                first = outputKV(fw, indent, first, TEXT_KEY, component.getText());
            }
            first = outputKV(fw, indent, first, ID_KEY, component.getId());
            first = outputKV(fw, indent, first, TAG_NAME_KEY, component.getTagName());
            first = outputKV(fw, indent, first, TAG_TYPE_KEY, component.getTagType());
            if (component.getFormId() != -1) {
                first = outputKV(fw, indent, first, FORM_ID_KEY, component.getFormId());
            }
            if (component.isStorageEvent()) {
                outputKV(fw, indent, first, STORAGE_EVENT_KEY, component.isStorageEvent());
            }
        }
        return indent;
    }
}
