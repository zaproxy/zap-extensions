/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi.generators;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.swagger.v3.core.util.Json;
import io.swagger.v3.oas.models.examples.Example;
import io.swagger.v3.oas.models.headers.Header;
import io.swagger.v3.oas.models.media.ArraySchema;
import io.swagger.v3.oas.models.media.BinarySchema;
import io.swagger.v3.oas.models.media.ComposedSchema;
import io.swagger.v3.oas.models.media.Encoding;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.ObjectSchema;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.media.XML;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
// Use fully-qualified org.w3c.dom types to avoid name collisions with local Element class
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BodyGenerator {

    private Generators generators;
    private DataGenerator dataGenerator;
    private static final Logger LOGGER = LogManager.getLogger(BodyGenerator.class);
    private static final List<String> PRIMITIVE_TYPES =
            Arrays.asList("boolean", "integer", "number", "string");
    public static final String TEXT_FILE_CONTENTS =
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus eu tortor efficitur";
    public static final String IMAGE_FILE_CONTENTS =
            new String(
                    new byte[] {110, -12, 34, -18, 11, 69, 20, 11, 51, 26, 27, 14},
                    StandardCharsets.UTF_8);

    public BodyGenerator(Generators generators) {
        this.generators = generators;
        this.dataGenerator = generators.getDataGenerator();
    }

    public String generateXml(MediaType mediaType) {
        String exampleBody = extractExampleBody(mediaType);
        if (exampleBody != null) {
            return exampleBody;
        }
        if (mediaType == null || mediaType.getSchema() == null) {
            return "";
        }
        return generateXml(mediaType.getSchema());
    }

    public String generateXml(Schema<?> schema) {
        if (schema == null) {
            return "";
        }
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            org.w3c.dom.Document doc = db.newDocument();

            String rootName = Optional.ofNullable(schema.getName()).orElse("root");
            // If schema has xml.name use it
            io.swagger.v3.oas.models.media.XML rootXml = schema.getXml();
            String rootNamespace = null;
            if (rootXml != null && rootXml.getName() != null) {
                rootName = rootXml.getName();
            }

            // Create root element, honoring namespace/prefix if present
            org.w3c.dom.Element root = createElementWithXml(doc, rootName, rootXml, null);
            doc.appendChild(root);

            // Track namespace declarations on root when creating descendants
            buildElementForSchema(doc, root, schema);

            // transform to string
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.setOutputProperty(OutputKeys.INDENT, "no");
            StreamResult result = new StreamResult(new java.io.StringWriter());
            DOMSource source = new DOMSource(doc);
            transformer.transform(source, result);
            return result.getWriter().toString();
        } catch (ParserConfigurationException | TransformerException e) {
            LOGGER.warn("Failed to generate XML body: {}", e.getMessage());
            if (this.generators != null) {
                this.generators.addErrorMessage("Failed to generate XML body: " + e.getMessage());
            }
            // Return null to indicate failure; callers will handle it
            return null;
        }
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void buildElementForSchema(
            org.w3c.dom.Document doc, org.w3c.dom.Element parent, Schema schema) {
        if (schema == null) {
            return;
        }
        // Handle composed schemas (oneOf/anyOf/allOf) by resolving/merging where
        // possible
        if (schema instanceof ComposedSchema) {
            ComposedSchema cs = (ComposedSchema) schema;
            // Prefer oneOf/anyOf resolution (pick first), otherwise try to merge allOf
            // components
            if (cs.getOneOf() != null && !cs.getOneOf().isEmpty()) {
                buildElementForSchema(doc, parent, cs.getOneOf().get(0));
                return;
            } else if (cs.getAnyOf() != null && !cs.getAnyOf().isEmpty()) {
                buildElementForSchema(doc, parent, cs.getAnyOf().get(0));
                return;
            } else if (cs.getAllOf() != null && !cs.getAllOf().isEmpty()) {
                // Merge properties from allOf into a temporary map and continue as object
                Map<String, Schema> merged = new HashMap<>();
                Schema additional = null;
                for (Schema s : cs.getAllOf()) {
                    if (s.getProperties() != null) {
                        merged.putAll(s.getProperties());
                    }
                    if (s.getAdditionalProperties() instanceof Schema) {
                        additional = (Schema) s.getAdditionalProperties();
                    }
                }
                // process merged properties
                for (Map.Entry<String, Schema> property : merged.entrySet()) {
                    String propName = property.getKey();
                    Schema propSchema = property.getValue();
                    XML propXml = propSchema.getXml();
                    if (propXml != null
                            && propXml.getAttribute() != null
                            && propXml.getAttribute()) {
                        String value = dataGenerator.generateBodyValue(propName, propSchema);
                        if (value != null
                                && value.length() >= 2
                                && value.startsWith("\"")
                                && value.endsWith("\"")) {
                            value = value.substring(1, value.length() - 1);
                        }
                        String attrName = propXml.getName() != null ? propXml.getName() : propName;
                        if (propXml.getNamespace() != null) {
                            String prefix = propXml.getPrefix();
                            String qname = (prefix != null ? prefix + ":" + attrName : attrName);
                            parent.setAttributeNS(
                                    propXml.getNamespace(), qname, value == null ? "" : value);
                            ensureNamespaceDeclarationOnRoot(parent, propXml);
                        } else {
                            parent.setAttribute(attrName, value == null ? "" : value);
                        }
                    } else {
                        String childName = propName;
                        if (propXml != null && propXml.getName() != null) {
                            childName = propXml.getName();
                        }
                        org.w3c.dom.Element child =
                                createElementWithXml(doc, childName, propXml, parent);
                        parent.appendChild(child);
                        buildElementForSchema(doc, child, propSchema);
                    }
                }
                if (additional != null) {
                    // generate two entries for additionalProperties map
                    for (int i = 0; i < 2; i++) {
                        org.w3c.dom.Element entry = doc.createElement("entry");
                        parent.appendChild(entry);
                        org.w3c.dom.Element key = doc.createElement("key");
                        key.setTextContent("k" + i);
                        entry.appendChild(key);
                        org.w3c.dom.Element value = doc.createElement("value");
                        entry.appendChild(value);
                        buildElementForSchema(doc, value, additional);
                    }
                }
                return;
            }
        }
        // Binary schema handling
        if (schema instanceof BinarySchema) {
            String content = generateFromBinarySchema((BinarySchema) schema, false);
            parent.setTextContent(content == null ? "" : content);
            return;
        }

        // Primitive types (non-array, non-object)
        if (!(schema instanceof ArraySchema) && !(schema instanceof ObjectSchema)) {
            String value = dataGenerator.generateBodyValue(parent.getNodeName(), schema);
            // strip surrounding quotes if present
            if (value != null
                    && value.length() >= 2
                    && value.startsWith("\"")
                    && value.endsWith("\"")) {
                value = value.substring(1, value.length() - 1);
            }
            parent.setTextContent(value == null ? "" : value);
            return;
        }

        if (schema instanceof ArraySchema) {
            Schema items = ((ArraySchema) schema).getItems();
            if (items == null) {
                return;
            }
            // Determine item element name
            String itemName = Optional.ofNullable(items.getName()).orElse(parent.getNodeName());
            XML xml = items.getXml();
            if (xml != null && xml.getName() != null) {
                itemName = xml.getName();
            }
            // produce two items to mirror JSON array behaviour
            // If this array is configured as not wrapped (xml.wrapped == false) then
            // append item elements to the parent of 'parent' instead of using the
            // container represented by 'parent'. This handles cases where callers
            // created a property element for the array but the XML schema expects
            // repeated item elements without a wrapper.
            boolean wrapped = true;
            XML parentXml = schema.getXml();
            if (parentXml != null && parentXml.getWrapped() != null) {
                wrapped = parentXml.getWrapped();
            }

            org.w3c.dom.Node insertionParent = parent;
            if (!wrapped && parent.getParentNode() instanceof org.w3c.dom.Element) {
                // use the parent's parent as the insertion point and remove the container
                // element
                insertionParent = parent.getParentNode();
                insertionParent.removeChild(parent);
            }

            for (int i = 0; i < 2; i++) {
                org.w3c.dom.Element itemEl = createElementWithXml(doc, itemName, xml, parent);
                insertionParent.appendChild(itemEl);
                buildElementForSchema(doc, itemEl, items);
            }
            return;
        }

        // ObjectSchema or schema with properties
        Map<String, Schema> properties = schema.getProperties();
        if (properties != null) {
            for (Map.Entry<String, Schema> property : properties.entrySet()) {
                String propName = property.getKey();
                Schema propSchema = property.getValue();
                XML propXml = propSchema.getXml();
                if (propXml != null && propXml.getAttribute() != null && propXml.getAttribute()) {
                    // attribute on parent
                    String value = dataGenerator.generateBodyValue(propName, propSchema);
                    if (value != null
                            && value.length() >= 2
                            && value.startsWith("\"")
                            && value.endsWith("\"")) {
                        value = value.substring(1, value.length() - 1);
                    }
                    String attrName = propXml.getName() != null ? propXml.getName() : propName;
                    // If attribute has namespace/prefix, use setAttributeNS
                    if (propXml.getNamespace() != null) {
                        String prefix = propXml.getPrefix();
                        String qname = (prefix != null ? prefix + ":" + attrName : attrName);
                        parent.setAttributeNS(
                                propXml.getNamespace(), qname, value == null ? "" : value);
                        // ensure xmlns declaration exists on root
                        ensureNamespaceDeclarationOnRoot(parent, propXml);
                    } else {
                        parent.setAttribute(attrName, value == null ? "" : value);
                    }
                } else {
                    String childName = propName;
                    if (propXml != null && propXml.getName() != null) {
                        childName = propXml.getName();
                    }
                    // If this property is an array and is marked as unwrapped, we
                    // should not create the property container element and instead
                    // append the item elements directly under the current parent.
                    if (propSchema instanceof ArraySchema
                            && propXml != null
                            && propXml.getWrapped() != null
                            && !propXml.getWrapped()) {
                        ArraySchema arr = (ArraySchema) propSchema;
                        Schema items = arr.getItems();
                        if (items != null) {
                            String itemName =
                                    Optional.ofNullable(items.getName()).orElse(childName);
                            XML itemXml = items.getXml();
                            if (itemXml != null && itemXml.getName() != null) {
                                itemName = itemXml.getName();
                            }
                            // append two item elements directly under parent
                            for (int i = 0; i < 2; i++) {
                                org.w3c.dom.Element itemEl =
                                        createElementWithXml(doc, itemName, itemXml, parent);
                                parent.appendChild(itemEl);
                                buildElementForSchema(doc, itemEl, items);
                            }
                            continue;
                        }
                    }

                    org.w3c.dom.Element child =
                            createElementWithXml(doc, childName, propXml, parent);
                    parent.appendChild(child);
                    buildElementForSchema(doc, child, propSchema);
                }
            }
            // handle additionalProperties if present (map values)
            if (schema.getAdditionalProperties() instanceof Schema) {
                Schema add = (Schema) schema.getAdditionalProperties();
                for (int i = 0; i < 2; i++) {
                    org.w3c.dom.Element entry = doc.createElement("entry");
                    parent.appendChild(entry);
                    org.w3c.dom.Element key = doc.createElement("key");
                    key.setTextContent("k" + i);
                    entry.appendChild(key);
                    org.w3c.dom.Element value = doc.createElement("value");
                    entry.appendChild(value);
                    buildElementForSchema(doc, value, add);
                }
            }
        } else if (schema.getAdditionalProperties() instanceof Schema) {
            // No named properties, but additionalProperties defines the value type -> emit
            // map entries
            Schema add = (Schema) schema.getAdditionalProperties();
            for (int i = 0; i < 2; i++) {
                org.w3c.dom.Element entry = doc.createElement("entry");
                parent.appendChild(entry);
                org.w3c.dom.Element key = doc.createElement("key");
                key.setTextContent("k" + i);
                entry.appendChild(key);
                org.w3c.dom.Element value = doc.createElement("value");
                entry.appendChild(value);
                buildElementForSchema(doc, value, add);
            }
        }
    }

    /**
     * Create an element honoring the given XML metadata (namespace and prefix) and ensure any
     * namespace declarations are added to the root element.
     *
     * @param doc the document
     * @param name the local name for the element
     * @param xml the XML metadata (may be null)
     * @param contextParent a nearby element whose root will receive namespace declarations (may be
     *     null)
     * @return the created Element
     */
    private org.w3c.dom.Element createElementWithXml(
            org.w3c.dom.Document doc, String name, XML xml, org.w3c.dom.Element contextParent) {
        if (xml != null && xml.getNamespace() != null) {
            String ns = xml.getNamespace();
            String prefix = xml.getPrefix();
            String qname = (prefix != null) ? (prefix + ":" + name) : name;
            org.w3c.dom.Element el = doc.createElementNS(ns, qname);
            // ensure namespace declaration on root
            ensureNamespaceDeclarationOnRoot((contextParent != null) ? contextParent : el, xml);
            return el;
        }
        return doc.createElement(name);
    }

    /**
     * Ensure that the namespace declaration for the provided XML metadata exists on the root
     * element.
     */
    private void ensureNamespaceDeclarationOnRoot(org.w3c.dom.Element anyChild, XML xml) {
        if (xml == null || xml.getNamespace() == null) {
            return;
        }
        org.w3c.dom.Node node = anyChild;
        // find the document root element
        while (node != null && !(node instanceof org.w3c.dom.Document)) {
            if (node.getParentNode() == null) {
                break;
            }
            node = node.getParentNode();
        }
        org.w3c.dom.Element root = null;
        if (node instanceof org.w3c.dom.Document) {
            root = ((org.w3c.dom.Document) node).getDocumentElement();
        } else {
            // walk up parents from anyChild to find root element
            node = anyChild;
            while (node != null && !(node instanceof org.w3c.dom.Document)) {
                if (node instanceof org.w3c.dom.Element
                        && node.getParentNode() instanceof org.w3c.dom.Document) {
                    root = (org.w3c.dom.Element) node;
                    break;
                }
                node = node.getParentNode();
            }
        }
        if (root == null) {
            return;
        }
        String ns = xml.getNamespace();
        String prefix = xml.getPrefix();
        if (prefix != null) {
            String attr = "xmlns:" + prefix;
            if (!root.hasAttribute(attr)) {
                root.setAttribute(attr, ns);
            }
        } else {
            if (!root.hasAttribute("xmlns")) {
                root.setAttribute("xmlns", ns);
            }
        }
    }

    private enum JsonElement {
        OBJECT_BEGIN,
        OBJECT_END,
        ARRAY_BEGIN,
        ARRAY_END,
        PROPERTY_CONTAINER,
        INNER_SEPARATOR,
        OUTER_SEPARATOR
    }

    @SuppressWarnings("serial")
    private static final Map<JsonElement, String> SYNTAX =
            Collections.unmodifiableMap(
                    new HashMap<JsonElement, String>() {
                        {
                            put(JsonElement.OBJECT_BEGIN, "{");
                            put(JsonElement.OBJECT_END, "}");
                            put(JsonElement.ARRAY_BEGIN, "[");
                            put(JsonElement.ARRAY_END, "]");
                            put(JsonElement.PROPERTY_CONTAINER, "\"");
                            put(JsonElement.INNER_SEPARATOR, ":");
                            put(JsonElement.OUTER_SEPARATOR, ",");
                        }
                    });

    public String generate(MediaType mediaType) {
        String exampleBody = extractExampleBody(mediaType);
        return exampleBody == null ? this.generate(mediaType.getSchema()) : exampleBody;
    }

    public String generate(Schema<?> schema) {
        if (schema == null) {
            return "";
        }

        LOGGER.debug("Generate body for object {}", schema.getName());

        if (schema instanceof ArraySchema) {
            return generateFromArraySchema((ArraySchema) schema);
        } else if (schema instanceof BinarySchema) {
            return generateFromBinarySchema((BinarySchema) schema, false);
        }

        @SuppressWarnings("rawtypes")
        Map<String, Schema> properties = schema.getProperties();
        if (properties != null) {
            return generateFromObjectSchema(properties);
        } else if (schema.getAdditionalProperties() instanceof Schema) {
            return generate((Schema<?>) schema.getAdditionalProperties());
        }

        if (schema instanceof ComposedSchema) {
            return generateJsonPrimitiveValue(resolveComposedSchema((ComposedSchema) schema));
        }
        if (schema.getNot() != null) {
            resolveNotSchema(schema);
        }

        if (!PRIMITIVE_TYPES.contains(Generators.getType(schema))) {
            schema.setType("string");
        }

        return generateJsonPrimitiveValue(schema);
    }

    private String generateFromArraySchema(ArraySchema schema) {
        if (schema.getExample() instanceof String) {
            return (String) schema.getExample();
        }

        if (schema.getExample() instanceof Iterable) {
            try {
                return Json.mapper().writeValueAsString(schema.getExample());
            } catch (JsonProcessingException e) {
                LOGGER.warn(
                        "Failed to encode Example Object. Falling back to default example generation",
                        e);
            }
        }

        return createJsonArrayWith(generate(schema.getItems()));
    }

    private static String generateFromBinarySchema(BinarySchema schema, boolean image) {
        if (image) {
            return IMAGE_FILE_CONTENTS;
        }
        return TEXT_FILE_CONTENTS;
    }

    @SuppressWarnings("rawtypes")
    private String generateFromObjectSchema(Map<String, Schema> properties) {
        StringBuilder json = new StringBuilder();
        boolean isFirst = true;
        json.append(SYNTAX.get(JsonElement.OBJECT_BEGIN));
        for (Map.Entry<String, Schema> property : properties.entrySet()) {
            if (isFirst) {
                isFirst = false;
            } else {
                json.append(SYNTAX.get(JsonElement.OUTER_SEPARATOR));
            }
            json.append(SYNTAX.get(JsonElement.PROPERTY_CONTAINER));
            json.append(property.getKey());
            json.append(SYNTAX.get(JsonElement.PROPERTY_CONTAINER));
            json.append(SYNTAX.get(JsonElement.INNER_SEPARATOR));
            String value;
            if (dataGenerator.isSupported(property.getValue())) {
                value = dataGenerator.generateBodyValue(property.getKey(), property.getValue());
            } else {

                value =
                        generators
                                .getValueGenerator()
                                .getValue(
                                        property.getKey(),
                                        property.getValue().getType(),
                                        generate(property.getValue()));
                if ("string".equals(property.getValue().getType()) && !value.startsWith("\"")) {
                    value = "\"" + value + "\"";
                }
            }
            json.append(value);
        }
        json.append(SYNTAX.get(JsonElement.OBJECT_END));
        return json.toString();
    }

    private static String createJsonArrayWith(String jsonStr) {
        return SYNTAX.get(JsonElement.ARRAY_BEGIN)
                + jsonStr
                + SYNTAX.get(JsonElement.OUTER_SEPARATOR)
                + jsonStr
                + SYNTAX.get(JsonElement.ARRAY_END);
    }

    private String generateJsonPrimitiveValue(Schema<?> schema) {
        return dataGenerator.generateBodyValue("", schema);
    }

    private static Schema<?> resolveComposedSchema(ComposedSchema schema) {

        if (schema.getOneOf() != null) {
            return schema.getOneOf().get(0);
        } else if (schema.getAnyOf() != null) {
            return schema.getAnyOf().get(0);
        }
        // Should not be reached, allOf schema is resolved by the parser
        LOGGER.error("Unknown composed schema type: {}", schema);
        return null;
    }

    private static void resolveNotSchema(Schema<?> schema) {
        if (schema.getNot().getType().equals("string")) {
            schema.setType("integer");
        } else {
            schema.setType("string");
        }
    }

    @SuppressWarnings("serial")
    private static final Map<JsonElement, String> FORMSYNTAX =
            Collections.unmodifiableMap(
                    new HashMap<JsonElement, String>() {
                        {
                            put(JsonElement.INNER_SEPARATOR, "=");
                            put(JsonElement.OUTER_SEPARATOR, "&");
                        }
                    });

    @SuppressWarnings("rawtypes")
    public String generateForm(Schema<?> schema) {
        if (schema == null) {
            return "";
        }
        Map<String, Schema> properties = schema.getProperties();
        if (properties != null) {
            StringBuilder formData = new StringBuilder();
            for (Map.Entry<String, Schema> property : properties.entrySet()) {
                formData.append(urlEncode(property.getKey()));
                formData.append(FORMSYNTAX.get(JsonElement.INNER_SEPARATOR));
                formData.append(
                        urlEncode(
                                dataGenerator.generateValue(
                                        property.getKey(), property.getValue(), true)));
                formData.append(FORMSYNTAX.get(JsonElement.OUTER_SEPARATOR));
            }
            return formData.substring(0, formData.length() - 1);
        }
        return "";
    }

    @SuppressWarnings("rawtypes")
    public String generateMultiPart(Schema<?> schema, Map<String, Encoding> encoding) {
        if (schema == null) {
            return "";
        }
        String boundary = UUID.randomUUID().toString();
        Map<String, Schema> properties = schema.getProperties();
        if (properties != null) {
            StringBuilder multipartData = new StringBuilder();
            for (Map.Entry<String, Schema> property : properties.entrySet()) {
                Schema propertySchema = property.getValue();
                multipartData.append("--" + boundary);
                multipartData.append("\r\n");
                multipartData.append("Content-Disposition");
                multipartData.append(": ");
                multipartData.append("form-data");
                multipartData.append("; ");
                multipartData.append("name=");
                multipartData.append("\"");
                multipartData.append(property.getKey());
                multipartData.append("\"");
                if (propertySchema instanceof BinarySchema) {
                    multipartData.append("; ");
                    multipartData.append("filename=");
                    multipartData.append("\"");
                    multipartData.append("SampleZAPFile");
                    multipartData.append("\"");
                }
                multipartData.append("\r\n");

                Encoding propertyEncoding;
                String propertyContentType = null;
                Map<String, Header> propertyHeaders = null;

                if (encoding != null) {
                    propertyEncoding = encoding.get(property.getKey());
                    if (propertyEncoding != null) {
                        propertyContentType = propertyEncoding.getContentType();
                        propertyHeaders = propertyEncoding.getHeaders();
                    }
                }

                if (propertyContentType == null) {
                    propertyContentType = getPropertyContentType(propertySchema);
                }
                multipartData.append("Content-Type");
                multipartData.append(": ");
                multipartData.append(propertyContentType);
                multipartData.append("\r\n");

                if (propertyHeaders != null) {
                    for (Map.Entry<String, Header> header : propertyHeaders.entrySet()) {
                        String headerName = header.getKey();
                        multipartData.append(headerName);
                        multipartData.append(": ");
                        multipartData.append(
                                dataGenerator.generateValue(
                                        headerName, header.getValue().getSchema(), false));
                        multipartData.append("\r\n");
                    }
                }

                multipartData.append("\r\n");
                if (propertyContentType.contains("image")) {
                    multipartData.append(
                            generateFromBinarySchema(((BinarySchema) propertySchema), true));
                } else {
                    multipartData.append(generate(propertySchema));
                }
                multipartData.append("\r\n");
            }
            multipartData.append("--" + boundary + "--");
            return multipartData.toString();
        }
        return "";
    }

    private static String getPropertyContentType(Schema<?> schema) {
        String type;

        if (schema instanceof ObjectSchema) {
            type = "application/json";
        } else if (schema instanceof BinarySchema) {
            type = "application/octet-stream";
        } else if (schema instanceof ArraySchema) {
            type = getPropertyContentType(((ArraySchema) schema).getItems());
        } else {
            type = "text/plain";
        }
        return type;
    }

    private static String urlEncode(String string) {
        try {
            return URLEncoder.encode(string, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException ignore) {
            // Shouldn't happen, standard charset.
            return "";
        }
    }

    @SuppressWarnings("rawtypes")
    private static String extractExampleBody(MediaType mediaType) {
        return Optional.ofNullable(mediaType.getExamples())
                .map(Map::values)
                .map(Collection::stream)
                .map(stream -> stream.map(Example::getValue).filter(Objects::nonNull).findFirst())
                .orElse(Optional.ofNullable(mediaType.getExample()))
                .map(Object::toString)
                .orElse(
                        Optional.ofNullable(mediaType.getSchema())
                                .map(Schema::getExample)
                                .map(Object::toString)
                                .orElse(null));
    }
}
