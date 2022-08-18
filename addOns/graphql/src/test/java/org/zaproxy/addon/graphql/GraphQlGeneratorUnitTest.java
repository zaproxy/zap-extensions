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
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.testutils.TestUtils;

class GraphQlGeneratorUnitTest extends TestUtils {
    GraphQlGenerator generator;
    GraphQlParam param;
    private ValueGenerator valueGenerator;

    @BeforeEach
    void setup() throws Exception {
        setUpZap();
        param = new GraphQlParam(5, true, 5, 5, true, null, null, null);
        valueGenerator = mock(ValueGenerator.class);
    }

    private GraphQlGenerator createGraphQlGenerator(String sdl) {
        return new GraphQlGenerator(valueGenerator, sdl, null, param);
    }

    @Test
    void scalarFieldsOnly() throws Exception {
        generator = createGraphQlGenerator(getHtml("scalarFieldsOnly.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { name id age height human } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    void zeroDepthObjects() throws Exception {
        generator = createGraphQlGenerator(getHtml("zeroDepthObjects.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { gymName dumbbell { fixedWeight weight } treadmill { maxSpeed manufacturer } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    void nestedObjects() throws Exception {
        generator = createGraphQlGenerator(getHtml("nestedObjects.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { book { id name pageCount author { id firstName lastName } } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    void circularRelationship() throws Exception {
        generator = createGraphQlGenerator(getHtml("circularRelationship.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { thread { id message { text thread { id message { text thread { id } } } } } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    void scalarArguments() throws Exception {
        generator = createGraphQlGenerator(getHtml("scalarArguments.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { polygon (sides: 1, regular: true) { perimeter area } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    void nonNullableScalarArguments() throws Exception {
        generator = createGraphQlGenerator(getHtml("nonNullableScalarArguments.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { getLyrics (song: \"ZAP\", artist: \"ZAP\") } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    void enumArgument() throws Exception {
        generator = createGraphQlGenerator(getHtml("enumArgument.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { location (direction: NORTH) } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    void listAsArgument() throws Exception {
        generator = createGraphQlGenerator(getHtml("listAsArgument.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { sum (numbers: [3.14, 3.14, 3.14]) concat (words: [\"ZAP\", \"ZAP\", \"ZAP\"]) "
                        + "compare (objects: [{ size: 1, colour: \"ZAP\" }, { size: 1, colour: \"ZAP\" }, { size: 1, colour: \"ZAP\" }]) } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    void inputObjectArgument() throws Exception {
        generator = createGraphQlGenerator(getHtml("inputObjectArgument.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { plot (point: { x: 3.14, y: 3.14 }) } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    void listsAndNonNull() throws Exception {
        generator = createGraphQlGenerator(getHtml("listsAndNonNull.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { jellyBean { count } marshmallow { count } nougat { count } pie { count } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    void nonNullableFields() throws Exception {
        generator = createGraphQlGenerator(getHtml("nonNullableFields.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { name phone child { id name school } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    void objectsImplementInterface() throws Exception {
        generator = createGraphQlGenerator(getHtml("objectsImplementInterface.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { character { ... on Hero { id name superPower weakness } ... on Villain { id name grudge origin } } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    void implementMultipleInterfaces() throws Exception {
        generator = createGraphQlGenerator(getHtml("implementMultipleInterfaces.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { someAnimal { ... on Swallow { wingspan speed } } someBird { ... on Swallow { wingspan speed } } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    void interfaceImplementsInterface() throws Exception {
        generator = createGraphQlGenerator(getHtml("interfaceImplementsInterface.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { picture { ... on Photo { id url thumbnail filter } } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    void unionType() throws Exception {
        generator = createGraphQlGenerator(getHtml("unionType.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { firstSearchResult { ... on Photo { height width } ... on Person { name age } } } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    void enumType() throws Exception {
        generator = createGraphQlGenerator(getHtml("enumType.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { direction } ";
        assertEquals(query, expectedQuery);
    }

    @Test
    void mutation() throws Exception {
        generator = createGraphQlGenerator(getHtml("mutation.graphql"));
        String mutation = generator.generate(GraphQlGenerator.RequestType.MUTATION);
        String expectedMutation =
                "mutation { createStudent (id: 1, name: \"ZAP\") { id name college { name location } } } ";
        assertEquals(mutation, expectedMutation);
    }

    @Test
    void subscription() throws Exception {
        generator = createGraphQlGenerator(getHtml("subscription.graphql"));
        String subscription = generator.generate(GraphQlGenerator.RequestType.SUBSCRIPTION);
        String expectedSubscription = "subscription { newMessage (roomId: 1) { sender text } } ";
        assertEquals(subscription, expectedSubscription);
    }

    // Tests for Arguments that use variables (i.e. not inline arguments)

    @Test
    void separatedScalarArguments() throws Exception {
        generator = createGraphQlGenerator(getHtml("scalarArguments.graphql"));
        String[] request = generator.generateWithVariables(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query ($polygon_regular: Boolean, $polygon_sides: Int) "
                        + "{ polygon (sides: $polygon_sides, regular: $polygon_regular) { perimeter area } } ";
        String expectedVariables = "{\"polygon_regular\": true, \"polygon_sides\": 1}";
        assertEquals(request[0], expectedQuery);
        assertEquals(request[1], expectedVariables);
    }

    @Test
    void separatedNonNullableScalarArguments() throws Exception {
        generator = createGraphQlGenerator(getHtml("nonNullableScalarArguments.graphql"));
        String[] request = generator.generateWithVariables(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query ($getLyrics_artist: String!, $getLyrics_song: String!) "
                        + "{ getLyrics (song: $getLyrics_song, artist: $getLyrics_artist) } ";
        String expectedVariables = "{\"getLyrics_artist\": \"ZAP\", \"getLyrics_song\": \"ZAP\"}";
        assertEquals(request[0], expectedQuery);
        assertEquals(request[1], expectedVariables);
    }

    @Test
    void separatedEnumArgumentVariable() throws Exception {
        generator = createGraphQlGenerator(getHtml("enumArgument.graphql"));
        String[] request = generator.generateWithVariables(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query ($location_direction: Direction) { location (direction: $location_direction) } ";
        String expectedVariables = "{\"location_direction\": \"NORTH\"}";
        assertEquals(request[0], expectedQuery);
        assertEquals(request[1], expectedVariables);
    }

    @Test
    void separatedListAsArgument() throws Exception {
        generator = createGraphQlGenerator(getHtml("listAsArgument.graphql"));
        String[] request = generator.generateWithVariables(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query ($compare_objects: [Object], $concat_words: [String!]!, $sum_numbers: [Float]) "
                        + "{ sum (numbers: $sum_numbers) concat (words: $concat_words) compare (objects: $compare_objects) } ";
        String expectedVariables =
                "{\"compare_objects\": [{ \"size\": 1, \"colour\": \"ZAP\" }, "
                        + "{ \"size\": 1, \"colour\": \"ZAP\" }, { \"size\": 1, \"colour\": \"ZAP\" }], "
                        + "\"concat_words\": [\"ZAP\", \"ZAP\", \"ZAP\"], \"sum_numbers\": [3.14, 3.14, 3.14]}";
        assertEquals(request[0], expectedQuery);
        assertEquals(request[1], expectedVariables);
    }

    @Test
    void separatedInputObjectArgument() throws Exception {
        generator = createGraphQlGenerator(getHtml("inputObjectArgument.graphql"));
        String[] request = generator.generateWithVariables(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query ($plot_point: Point2D) { plot (point: $plot_point) } ";
        String expectedVariables = "{\"plot_point\": { \"x\": 3.14, \"y\": 3.14 }}";
        assertEquals(request[0], expectedQuery);
        assertEquals(request[1], expectedVariables);
    }

    @Test
    void variableNamesClash() throws Exception {
        generator = createGraphQlGenerator(getHtml("variableNamesClash.graphql"));
        String[] request = generator.generateWithVariables(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query ($field2_name_id: ID, $field1_name_id: ID) { field1 { name (id: $field1_name_id) } field2 { name (id: $field2_name_id) } } ";
        String expectedVariables = "{\"field2_name_id\": 1, \"field1_name_id\": 1}";
        assertEquals(request[0], expectedQuery);
        assertEquals(request[1], expectedVariables);
    }

    // Tests for queries that exceed maximum query depth (Lenient Max Query Depth Enabled)

    @Test
    void lenientDepthDeepNestedLeaf() throws Exception {
        param = new GraphQlParam(0, true, 5, 5, true, null, null, null);
        generator = createGraphQlGenerator(getHtml("deepNestedLeaf.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { user (id: 1) { follower { favouriteIceCream { flavour } } } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void strictDepthScalarArguments() throws Exception {
        param = new GraphQlParam(1, false, 5, 5, true, null, null, null);
        generator = createGraphQlGenerator(getHtml("scalarArguments.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { polygon (sides: 1, regular: true) } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void lenientDepthScalarArguments() throws Exception {
        param = new GraphQlParam(0, true, 5, 5, true, null, null, null);
        generator = createGraphQlGenerator(getHtml("scalarArguments.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { polygon (sides: 1, regular: true) { perimeter } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void lenientDepthObjectsImplementInterface() throws Exception {
        param = new GraphQlParam(0, true, 5, 5, true, null, null, null);
        generator = createGraphQlGenerator(getHtml("objectsImplementInterface.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { character { ... on Hero { id } } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void lenientDepthUnionType() throws Exception {
        param = new GraphQlParam(0, true, 5, 5, true, null, null, null);
        generator = createGraphQlGenerator(getHtml("unionType.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { firstSearchResult { ... on Photo { height } } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void lenientDepthEnumType() throws Exception {
        param = new GraphQlParam(0, true, 5, 5, true, null, null, null);
        generator = createGraphQlGenerator(getHtml("enumType.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { direction } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void lenientDepthScalarArgumentsVariables() throws Exception {
        param = new GraphQlParam(0, true, 5, 5, true, null, null, null);
        generator = createGraphQlGenerator(getHtml("scalarArguments.graphql"));
        String[] request = generator.generateWithVariables(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query ($polygon_regular: Boolean, $polygon_sides: Int) "
                        + "{ polygon (sides: $polygon_sides, regular: $polygon_regular) { perimeter } } ";
        String expectedVariables = "{\"polygon_regular\": true, \"polygon_sides\": 1}";
        assertEquals(expectedQuery, request[0]);
        assertEquals(expectedVariables, request[1]);
    }

    @Test
    void lenientDepthExceeded() throws Exception {
        param = new GraphQlParam(0, true, 3, 5, true, null, null, null);
        generator = createGraphQlGenerator(getHtml("deepNestedLeaf.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query ";
        assertEquals(expectedQuery, query);
    }
}
