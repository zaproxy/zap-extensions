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

import graphql.schema.GraphQLSchema;
import graphql.schema.idl.SchemaParser;
import graphql.schema.idl.UnExecutableSchemaGenerator;
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
        param = new GraphQlParam(true, 5, true, 5, 5, true, null, null, null);
        valueGenerator = mock(ValueGenerator.class);
    }

    private GraphQlGenerator createGraphQlGenerator(String sdl) {
        return new GraphQlGenerator(valueGenerator, sdl, null, param);
    }

    @Test
    void scalarFieldsOnly() {
        generator = createGraphQlGenerator(getHtml("scalarFieldsOnly.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { name id age height human } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void zeroDepthObjects() {
        generator = createGraphQlGenerator(getHtml("zeroDepthObjects.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { gymName dumbbell { fixedWeight weight } treadmill { maxSpeed manufacturer } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void nestedObjects() {
        generator = createGraphQlGenerator(getHtml("nestedObjects.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { book { id name pageCount author { id firstName lastName } } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void circularRelationship() {
        generator = createGraphQlGenerator(getHtml("circularRelationship.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { thread { id message { text thread { id message { text thread { id } } } } } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void scalarArguments() {
        generator = createGraphQlGenerator(getHtml("scalarArguments.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { polygon (sides: 1, regular: true) { perimeter area } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void nonNullableScalarArguments() {
        generator = createGraphQlGenerator(getHtml("nonNullableScalarArguments.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { getLyrics (song: \"ZAP\", artist: \"ZAP\") } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void nonNullableScalarArgumentsWithValueGenerator() {
        // Given
        String song = "Never Gonna Give You Up";
        String artist = "Rick Astley";
        ValueGenerator vg =
                (uri,
                        url,
                        fieldId,
                        defaultValue,
                        definedValues,
                        envAttributes,
                        fieldAttributes) -> {
                    if (fieldId.equals("song")) {
                        return song;
                    } else if (fieldId.equals("artist")) {
                        return artist;
                    }
                    return null;
                };
        generator =
                new GraphQlGenerator(
                        vg, getHtml("nonNullableScalarArguments.graphql"), null, param);
        // When
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        // Then
        String expectedQuery =
                "query { getLyrics (song: \"" + song + "\", artist: \"" + artist + "\") } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void enumArgument() {
        generator = createGraphQlGenerator(getHtml("enumArgument.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { location (direction: NORTH) } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void listAsArgument() {
        generator = createGraphQlGenerator(getHtml("listAsArgument.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { sum (numbers: [3.14, 3.14, 3.14]) concat (words: [\"ZAP\", \"ZAP\", \"ZAP\"]) "
                        + "compare (objects: [{ size: 1, colour: \"ZAP\" }, { size: 1, colour: \"ZAP\" }, { size: 1, colour: \"ZAP\" }]) } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void inputObjectArgument() {
        generator = createGraphQlGenerator(getHtml("inputObjectArgument.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { plot (point: { x: 3.14, y: 3.14 }) } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void listsAndNonNull() {
        generator = createGraphQlGenerator(getHtml("listsAndNonNull.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { jellyBean { count } marshmallow { count } nougat { count } pie { count } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void nonNullableFields() {
        generator = createGraphQlGenerator(getHtml("nonNullableFields.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { name phone child { id name school } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void objectsImplementInterface() {
        generator = createGraphQlGenerator(getHtml("objectsImplementInterface.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { character { ... on Hero { id name superPower weakness } ... on Villain { id name grudge origin } } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void implementMultipleInterfaces() {
        generator = createGraphQlGenerator(getHtml("implementMultipleInterfaces.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { someAnimal { ... on Swallow { wingspan speed } } someBird { ... on Swallow { wingspan speed } } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void interfaceImplementsInterface() {
        generator = createGraphQlGenerator(getHtml("interfaceImplementsInterface.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { picture { ... on Photo { id url thumbnail filter } } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void unionType() {
        generator = createGraphQlGenerator(getHtml("unionType.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { firstSearchResult { ... on Photo { height width } ... on Person { name age } } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void enumType() {
        generator = createGraphQlGenerator(getHtml("enumType.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { direction } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void mutation() {
        generator = createGraphQlGenerator(getHtml("mutation.graphql"));
        String mutation = generator.generate(GraphQlGenerator.RequestType.MUTATION);
        String expectedMutation =
                "mutation { createStudent (id: 1, name: \"ZAP\") { id name college { name location } } } ";
        assertEquals(expectedMutation, mutation);
    }

    @Test
    void subscription() {
        generator = createGraphQlGenerator(getHtml("subscription.graphql"));
        String subscription = generator.generate(GraphQlGenerator.RequestType.SUBSCRIPTION);
        String expectedSubscription = "subscription { newMessage (roomId: 1) { sender text } } ";
        assertEquals(expectedSubscription, subscription);
    }

    // Tests for Arguments that use variables (i.e. not inline arguments)

    @Test
    void separatedScalarArguments() {
        generator = createGraphQlGenerator(getHtml("scalarArguments.graphql"));
        String[] request = generator.generateWithVariables(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query ($polygon_regular: Boolean, $polygon_sides: Int) "
                        + "{ polygon (sides: $polygon_sides, regular: $polygon_regular) { perimeter area } } ";
        String expectedVariables = "{\"polygon_sides\":1,\"polygon_regular\":true}";
        assertEquals(expectedQuery, request[0]);
        assertEquals(expectedVariables, request[1]);
    }

    @Test
    void separatedNonNullableScalarArguments() {
        generator = createGraphQlGenerator(getHtml("nonNullableScalarArguments.graphql"));
        String[] request = generator.generateWithVariables(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query ($getLyrics_artist: String!, $getLyrics_song: String!) "
                        + "{ getLyrics (song: $getLyrics_song, artist: $getLyrics_artist) } ";
        String expectedVariables = "{\"getLyrics_song\":\"ZAP\",\"getLyrics_artist\":\"ZAP\"}";
        assertEquals(expectedQuery, request[0]);
        assertEquals(expectedVariables, request[1]);
    }

    @Test
    void separatedEnumArgumentVariable() {
        generator = createGraphQlGenerator(getHtml("enumArgument.graphql"));
        String[] request = generator.generateWithVariables(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query ($location_direction: Direction) { location (direction: $location_direction) } ";
        String expectedVariables = "{\"location_direction\":\"NORTH\"}";
        assertEquals(expectedQuery, request[0]);
        assertEquals(expectedVariables, request[1]);
    }

    @Test
    void separatedListAsArgument() {
        generator = createGraphQlGenerator(getHtml("listAsArgument.graphql"));
        String[] request = generator.generateWithVariables(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query ($compare_objects: [Object], $concat_words: [String!]!, $sum_numbers: [Float]) "
                        + "{ sum (numbers: $sum_numbers) concat (words: $concat_words) compare (objects: $compare_objects) } ";
        String expectedVariables =
                "{\"sum_numbers\":[3.14,3.14,3.14],\"concat_words\":[\"ZAP\",\"ZAP\",\"ZAP\"],"
                        + "\"compare_objects\":[{\"size\":1,\"colour\":\"ZAP\"},"
                        + "{\"size\":1,\"colour\":\"ZAP\"},{\"size\":1,\"colour\":\"ZAP\"}]}";
        assertEquals(expectedQuery, request[0]);
        assertEquals(expectedVariables, request[1]);
    }

    @Test
    void separatedInputObjectArgument() {
        generator = createGraphQlGenerator(getHtml("inputObjectArgument.graphql"));
        String[] request = generator.generateWithVariables(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query ($plot_point: Point2D) { plot (point: $plot_point) } ";
        String expectedVariables = "{\"plot_point\":{\"x\":3.14,\"y\":3.14}}";
        assertEquals(expectedQuery, request[0]);
        assertEquals(expectedVariables, request[1]);
    }

    @Test
    void variableNamesClash() {
        generator = createGraphQlGenerator(getHtml("variableNamesClash.graphql"));
        String[] request = generator.generateWithVariables(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query ($field2_name_id: ID, $field1_name_id: ID) { field1 { name (id: $field1_name_id) } field2 { name (id: $field2_name_id) } } ";
        String expectedVariables = "{\"field1_name_id\":1,\"field2_name_id\":1}";
        assertEquals(expectedQuery, request[0]);
        assertEquals(expectedVariables, request[1]);
    }

    // Tests for queries that exceed maximum query depth (Lenient Max Query Depth Enabled)

    @Test
    void lenientDepthDeepNestedLeaf() {
        param = new GraphQlParam(true, 0, true, 5, 5, true, null, null, null);
        generator = createGraphQlGenerator(getHtml("deepNestedLeaf.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query { user (id: 1) { follower { favouriteIceCream { flavour } } } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void strictDepthScalarArguments() {
        param = new GraphQlParam(true, 1, false, 5, 5, true, null, null, null);
        generator = createGraphQlGenerator(getHtml("scalarArguments.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { polygon (sides: 1, regular: true) } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void lenientDepthScalarArguments() {
        param = new GraphQlParam(true, 0, true, 5, 5, true, null, null, null);
        generator = createGraphQlGenerator(getHtml("scalarArguments.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { polygon (sides: 1, regular: true) { perimeter } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void lenientDepthObjectsImplementInterface() {
        param = new GraphQlParam(true, 0, true, 5, 5, true, null, null, null);
        generator = createGraphQlGenerator(getHtml("objectsImplementInterface.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { character { ... on Hero { id } } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void lenientDepthUnionType() {
        param = new GraphQlParam(true, 0, true, 5, 5, true, null, null, null);
        generator = createGraphQlGenerator(getHtml("unionType.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { firstSearchResult { ... on Photo { height } } } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void lenientDepthEnumType() {
        param = new GraphQlParam(true, 0, true, 5, 5, true, null, null, null);
        generator = createGraphQlGenerator(getHtml("enumType.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query { direction } ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void lenientDepthScalarArgumentsVariables() {
        param = new GraphQlParam(true, 0, true, 5, 5, true, null, null, null);
        generator = createGraphQlGenerator(getHtml("scalarArguments.graphql"));
        String[] request = generator.generateWithVariables(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery =
                "query ($polygon_regular: Boolean, $polygon_sides: Int) "
                        + "{ polygon (sides: $polygon_sides, regular: $polygon_regular) { perimeter } } ";
        String expectedVariables = "{\"polygon_sides\":1,\"polygon_regular\":true}";
        assertEquals(expectedQuery, request[0]);
        assertEquals(expectedVariables, request[1]);
    }

    @Test
    void lenientDepthExceeded() {
        param = new GraphQlParam(true, 0, true, 3, 5, true, null, null, null);
        generator = createGraphQlGenerator(getHtml("deepNestedLeaf.graphql"));
        String query = generator.generate(GraphQlGenerator.RequestType.QUERY);
        String expectedQuery = "query ";
        assertEquals(expectedQuery, query);
    }

    @Test
    void getFirstLeafQueryShouldWorkForWrappedTypes() {
        String sdl = getHtml("listsAndNonNull.graphql");
        GraphQLSchema schema =
                UnExecutableSchemaGenerator.makeUnExecutableSchema(new SchemaParser().parse(sdl));
        generator = createGraphQlGenerator(sdl);
        String query = generator.getFirstLeafQuery(schema.getQueryType(), null, null);
        String expectedQuery = "{ jellyBean { count } } ";
        assertEquals(expectedQuery, query);
    }
}
