/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.graphql;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.testutils.TestUtils;

public class GraphQlGeneratorUnitTest extends TestUtils {
    GraphQlGenerator generator;
    GraphQlParam param;

    @BeforeEach
    public void setup() throws Exception {
        setUpZap();
        param = new GraphQlParam(5, 5, true, null, null);
    }

    @Test
    public void scalarFieldsOnly() throws Exception {
        generator = new GraphQlGenerator(getHtml("scalarFieldsOnly.graphql"), null, param);
        String query = generator.generateFull(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "{ name id age height human } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    public void zeroDepthObjects() throws Exception {
        generator = new GraphQlGenerator(getHtml("zeroDepthObjects.graphql"), null, param);
        String query = generator.generateFull(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "{ gymName dumbbell { fixedWeight weight } treadmill { maxSpeed manufacturer } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    public void nestedObjects() throws Exception {
        generator = new GraphQlGenerator(getHtml("nestedObjects.graphql"), null, param);
        String query = generator.generateFull(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "{ book { id name pageCount author { id firstName lastName } } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    public void circularRelationship() throws Exception {
        generator = new GraphQlGenerator(getHtml("circularRelationship.graphql"), null, param);
        String query = generator.generateFull(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "{ thread { id message { text thread { id message { text thread { id } } } } } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    public void scalarArguments() throws Exception {
        generator = new GraphQlGenerator(getHtml("scalarArguments.graphql"), null, param);
        String query = generator.generateFull(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "{ polygon (sides: 1, regular: true) { perimeter area } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    public void nonNullableScalarArguments() throws Exception {
        generator =
                new GraphQlGenerator(getHtml("nonNullableScalarArguments.graphql"), null, param);
        String query = generator.generateFull(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "{ getLyrics (song: \"ZAP\", artist: \"ZAP\") } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    public void enumArgument() throws Exception {
        generator = new GraphQlGenerator(getHtml("enumArgument.graphql"), null, param);
        String query = generator.generateFull(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "{ location (direction: NORTH) } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    public void listAsArgument() throws Exception {
        generator = new GraphQlGenerator(getHtml("listAsArgument.graphql"), null, param);
        String query = generator.generateFull(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "{ sum (numbers: [3.14, 3.14, 3.14]) concat (words: [\"ZAP\", \"ZAP\", \"ZAP\"]) "
                        + "compare (objects: [{ size: 1, colour: \"ZAP\" }, { size: 1, colour: \"ZAP\" }, { size: 1, colour: \"ZAP\" }]) } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    public void inputObjectArgument() throws Exception {
        generator = new GraphQlGenerator(getHtml("inputObjectArgument.graphql"), null, param);
        String query = generator.generateFull(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "{ plot (point: { x: 3.14, y: 3.14 }) } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    public void listsAndNonNull() throws Exception {
        generator = new GraphQlGenerator(getHtml("listsAndNonNull.graphql"), null, param);
        String query = generator.generateFull(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "{ jellyBean { count } marshmallow { count } nougat { count } pie { count } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    public void nonNullableFields() throws Exception {
        generator = new GraphQlGenerator(getHtml("nonNullableFields.graphql"), null, param);
        String query = generator.generateFull(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "{ name phone child { id name school } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    public void objectsImplementInterface() throws Exception {
        generator = new GraphQlGenerator(getHtml("objectsImplementInterface.graphql"), null, param);
        String query = generator.generateFull(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "{ character { ... on Hero { id name superPower weakness } ... on Villain { id name grudge origin } } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    public void implementMultipleInterfaces() throws Exception {
        generator =
                new GraphQlGenerator(getHtml("implementMultipleInterfaces.graphql"), null, param);
        String query = generator.generateFull(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "{ someAnimal { ... on Swallow { wingspan speed } } someBird { ... on Swallow { wingspan speed } } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    public void interfaceImplementsInterface() throws Exception {
        generator =
                new GraphQlGenerator(getHtml("interfaceImplementsInterface.graphql"), null, param);
        String query = generator.generateFull(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "{ picture { ... on Photo { id url thumbnail filter } } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    public void unionType() throws Exception {
        generator = new GraphQlGenerator(getHtml("unionType.graphql"), null, param);
        String query = generator.generateFull(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "{ firstSearchResult { ... on Photo { height width } ... on Person { name age } } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    public void enumType() throws Exception {
        generator = new GraphQlGenerator(getHtml("enumType.graphql"), null, param);
        String query = generator.generateFull(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "{ direction } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    public void mutation() throws Exception {
        generator = new GraphQlGenerator(getHtml("mutation.graphql"), null, param);
        String mutation = generator.generateFull(GraphQlGenerator.RequestType.MUTATION);
        String expectedMutation =
                "mutation { createStudent (id: 1, name: \"ZAP\") { id name college { name location } } } ";
        assertEquals(mutation, expectedMutation);
    }

    @Test
    public void subscription() throws Exception {
        generator = new GraphQlGenerator(getHtml("subscription.graphql"), null, param);
        String subscription = generator.generateFull(GraphQlGenerator.RequestType.SUBSCRIPTION);
        String expectedSubscription = "subscription { newMessage (roomId: 1) { sender text } } ";
        assertEquals(subscription, expectedSubscription);
    }
}
