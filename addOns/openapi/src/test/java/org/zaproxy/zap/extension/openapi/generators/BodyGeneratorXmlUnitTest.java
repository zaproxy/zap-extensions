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
package org.zaproxy.zap.extension.openapi.generators;

import static org.junit.jupiter.api.Assertions.assertFalse;

import io.swagger.v3.oas.models.media.ArraySchema;
import io.swagger.v3.oas.models.media.ComposedSchema;
import io.swagger.v3.oas.models.media.ObjectSchema;
import io.swagger.v3.oas.models.media.Schema;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.openapi.ExtensionOpenApi;
import org.zaproxy.zap.testutils.TestUtils;

class BodyGeneratorXmlUnitTest extends TestUtils {

    Generators generators;

    @BeforeAll
    static void setUp() {
        mockMessages(new ExtensionOpenApi());
    }

    @BeforeEach
    void init() {
        generators = new Generators(null);
    }

    @Test
    void shouldGenerateXmlForSimpleObject() throws Exception {
        ObjectSchema schema = new ObjectSchema();
        schema.setName("person");
        Schema<?> name = new Schema<>();
        name.setType("string");
        schema.setProperties(Map.of("name", name));

        String xml = generators.getBodyGenerator().generateXml(schema);
        assertFalse(xml.isEmpty());
        // Parse and assert structure
        javax.xml.parsers.DocumentBuilderFactory dbf =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        org.w3c.dom.Document doc =
                db.parse(
                        new java.io.ByteArrayInputStream(
                                xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        org.w3c.dom.Element root = doc.getDocumentElement();
        org.junit.jupiter.api.Assertions.assertEquals("person", root.getNodeName());
        org.w3c.dom.NodeList names = doc.getElementsByTagName("name");
        org.junit.jupiter.api.Assertions.assertTrue(names.getLength() >= 1);
    }

    @Test
    void shouldGenerateXmlForArray() throws Exception {
        ArraySchema schema = new ArraySchema();
        Schema<?> items = new Schema<>();
        items.setType("string");
        items.setName("tag");
        schema.setItems(items);
        schema.setName("tags");

        String xml = generators.getBodyGenerator().generateXml(schema);
        assertFalse(xml.isEmpty());
        javax.xml.parsers.DocumentBuilderFactory dbf =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        org.w3c.dom.Document doc =
                db.parse(
                        new java.io.ByteArrayInputStream(
                                xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        org.w3c.dom.Element root = doc.getDocumentElement();
        org.junit.jupiter.api.Assertions.assertEquals("tags", root.getNodeName());
        org.w3c.dom.NodeList tagNodes = doc.getElementsByTagName("tag");
        org.junit.jupiter.api.Assertions.assertEquals(2, tagNodes.getLength());
    }

    @Test
    void shouldGenerateXmlWithAttribute() throws Exception {
        ObjectSchema schema = new ObjectSchema();
        schema.setName("person");
        Schema<?> id = new Schema<>();
        id.setType("integer");
        io.swagger.v3.oas.models.media.XML idXml = new io.swagger.v3.oas.models.media.XML();
        idXml.setAttribute(true);
        idXml.setName("id");
        id.setXml(idXml);
        Schema<?> name = new Schema<>();
        name.setType("string");
        schema.setProperties(Map.of("id", id, "name", name));

        String xml = generators.getBodyGenerator().generateXml(schema);
        assertFalse(xml.isEmpty());
        javax.xml.parsers.DocumentBuilderFactory dbf =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        org.w3c.dom.Document doc =
                db.parse(
                        new java.io.ByteArrayInputStream(
                                xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        org.w3c.dom.Element root = doc.getDocumentElement();
        org.junit.jupiter.api.Assertions.assertEquals("person", root.getNodeName());
        org.junit.jupiter.api.Assertions.assertTrue(root.hasAttribute("id"));
        org.w3c.dom.NodeList names = doc.getElementsByTagName("name");
        org.junit.jupiter.api.Assertions.assertTrue(names.getLength() >= 1);
    }

    @Test
    void shouldGenerateXmlForUnwrappedArray() throws Exception {
        ObjectSchema schema = new ObjectSchema();
        schema.setName("tagsContainer");
        ArraySchema tags = new ArraySchema();
        Schema<?> items = new Schema<>();
        items.setType("string");
        items.setName("tag");
        io.swagger.v3.oas.models.media.XML itemXml = new io.swagger.v3.oas.models.media.XML();
        itemXml.setName("tag");
        items.setXml(itemXml);
        io.swagger.v3.oas.models.media.XML tagsXml = new io.swagger.v3.oas.models.media.XML();
        tagsXml.setWrapped(false);
        tags.setXml(tagsXml);
        tags.setItems(items);
        schema.setProperties(Map.of("tags", tags));

        String xml = generators.getBodyGenerator().generateXml(schema);
        assertFalse(xml.isEmpty());
        javax.xml.parsers.DocumentBuilderFactory dbf =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        org.w3c.dom.Document doc =
                db.parse(
                        new java.io.ByteArrayInputStream(
                                xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        org.w3c.dom.Element root = doc.getDocumentElement();
        org.junit.jupiter.api.Assertions.assertEquals("tagsContainer", root.getNodeName());
        // ensure no <tags> wrapper exists
        org.w3c.dom.NodeList wrappers = doc.getElementsByTagName("tags");
        org.junit.jupiter.api.Assertions.assertEquals(0, wrappers.getLength());
        org.w3c.dom.NodeList tagNodes = doc.getElementsByTagName("tag");
        org.junit.jupiter.api.Assertions.assertEquals(2, tagNodes.getLength());
    }

    @Test
    void shouldGenerateXmlWithNamespaceAndPrefix() throws Exception {
        ObjectSchema schema = new ObjectSchema();
        schema.setName("person");
        Schema<?> name = new Schema<>();
        name.setType("string");
        schema.setProperties(Map.of("name", name));
        io.swagger.v3.oas.models.media.XML rootXml = new io.swagger.v3.oas.models.media.XML();
        rootXml.setNamespace("http://example.com/ns");
        rootXml.setPrefix("ex");
        rootXml.setName("person");
        schema.setXml(rootXml);

        String xml = generators.getBodyGenerator().generateXml(schema);
        assertFalse(xml.isEmpty());
        javax.xml.parsers.DocumentBuilderFactory dbf =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        org.w3c.dom.Document doc =
                db.parse(
                        new java.io.ByteArrayInputStream(
                                xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        org.w3c.dom.Element root = doc.getDocumentElement();
        org.junit.jupiter.api.Assertions.assertEquals("person", root.getLocalName());
        org.junit.jupiter.api.Assertions.assertEquals("ex", root.getPrefix());
        org.junit.jupiter.api.Assertions.assertEquals(
                "http://example.com/ns", root.getNamespaceURI());
    }

    @org.junit.jupiter.api.Test
    void shouldGenerateXmlForBinary() throws Exception {
        ObjectSchema schema = new ObjectSchema();
        schema.setName("fileContainer");
        io.swagger.v3.oas.models.media.BinarySchema file =
                new io.swagger.v3.oas.models.media.BinarySchema();
        schema.setProperties(Map.of("file", file));

        String xml = generators.getBodyGenerator().generateXml(schema);
        assertFalse(xml.isEmpty());
        javax.xml.parsers.DocumentBuilderFactory dbf =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        org.w3c.dom.Document doc =
                db.parse(
                        new java.io.ByteArrayInputStream(
                                xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        org.w3c.dom.NodeList files = doc.getElementsByTagName("file");
        org.junit.jupiter.api.Assertions.assertEquals(1, files.getLength());
    }

    @org.junit.jupiter.api.Test
    void shouldGenerateXmlForAdditionalProperties() throws Exception {
        ObjectSchema schema = new ObjectSchema();
        schema.setName("mapContainer");
        Schema<?> add = new Schema<>();
        add.setType("string");
        schema.setAdditionalProperties(add);

        String xml = generators.getBodyGenerator().generateXml(schema);
        assertFalse(xml.isEmpty());
        javax.xml.parsers.DocumentBuilderFactory dbf =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        org.w3c.dom.Document doc =
                db.parse(
                        new java.io.ByteArrayInputStream(
                                xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        org.w3c.dom.NodeList entries = doc.getElementsByTagName("entry");
        org.junit.jupiter.api.Assertions.assertEquals(2, entries.getLength());
        org.w3c.dom.NodeList keys = doc.getElementsByTagName("key");
        org.junit.jupiter.api.Assertions.assertEquals(2, keys.getLength());
        org.w3c.dom.NodeList values = doc.getElementsByTagName("value");
        org.junit.jupiter.api.Assertions.assertEquals(2, values.getLength());
    }

    @org.junit.jupiter.api.Test
    void shouldGenerateXmlForComposedSchemaAllOf() throws Exception {
        ComposedSchema cs = new ComposedSchema();
        Schema<?> s1 = new ObjectSchema();
        Schema<?> prop1 = new Schema<>();
        prop1.setType("string");
        ((ObjectSchema) s1).setProperties(Map.of("a", prop1));
        Schema<?> s2 = new ObjectSchema();
        Schema<?> prop2 = new Schema<>();
        prop2.setType("integer");
        ((ObjectSchema) s2).setProperties(Map.of("b", prop2));
        cs.setAllOf(List.of(s1, s2));

        String xml = generators.getBodyGenerator().generateXml(cs);
        assertFalse(xml.isEmpty());
        javax.xml.parsers.DocumentBuilderFactory dbf =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
        javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
        org.w3c.dom.Document doc =
                db.parse(
                        new java.io.ByteArrayInputStream(
                                xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        org.w3c.dom.NodeList a = doc.getElementsByTagName("a");
        org.w3c.dom.NodeList b = doc.getElementsByTagName("b");
        org.junit.jupiter.api.Assertions.assertEquals(1, a.getLength());
        org.junit.jupiter.api.Assertions.assertEquals(1, b.getLength());
    }
}
