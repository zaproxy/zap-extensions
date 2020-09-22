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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.testutils.TestUtils;

public class InlineInjectorUnitTest extends TestUtils {
    InlineInjector injector = new InlineInjector();

    @BeforeEach
    public void setup() throws Exception {
        setUpZap();
    }

    // Extraction Tests

    @Test
    public void noArguments() throws Exception {
        String query = "query { name id age height human }";
        HashMap<String, String> arguments = new HashMap<>();
        assertTrue(arguments.equals(injector.extract(query)));
    }

    @Test
    public void operationName() throws Exception {
        String query = "query sample { chemical (name: \"Hydrochloric Acid\") }";
        HashMap<String, String> arguments = new HashMap<>();
        arguments.put("sample.chemical.name", "\"Hydrochloric Acid\"");
        assertTrue(arguments.equals(injector.extract(query)));
    }

    @Test
    public void scalarArguments() throws Exception {
        String query =
                "query { polygon (sides: 1, regular: true, colour: \"blue\") { perimeter area } }";
        HashMap<String, String> arguments = new HashMap<>();
        arguments.put("polygon.sides", "1");
        arguments.put("polygon.regular", "true");
        arguments.put("polygon.colour", "\"blue\"");
        assertTrue(arguments.equals(injector.extract(query)));
    }

    @Test
    public void listAsArgument() throws Exception {
        String query = "query { sum (numbers: [3.14, 3.14, 3.14]) }";
        HashMap<String, String> arguments = new HashMap<>();
        arguments.put("sum.numbers", "[3.14,3.14,3.14]");
        assertTrue(arguments.equals(injector.extract(query)));
    }

    @Test
    public void inputObjectArgument() throws Exception {
        String query = "query { plot (point: { x: 3.14, y: 3.14 }) }";
        HashMap<String, String> arguments = new HashMap<>();
        arguments.put("plot.point", "{x:3.14,y:3.14}");
        assertTrue(arguments.equals(injector.extract(query)));
    }

    @Test
    public void inlineFragmentArguments() throws Exception {
        String query = "query { ... on field1 { name (id: 1) } }";
        HashMap<String, String> arguments = new HashMap<>();
        arguments.put("field1.name.id", "1");
        assertTrue(arguments.equals(injector.extract(query)));
    }

    @Test
    public void fragmentSpreadArguments() throws Exception {
        String query =
                "query { ...spread }  fragment spread on fragment1 {field1 { name (id: 1) } }";
        HashMap<String, String> arguments = new HashMap<>();
        arguments.put("spread.field1.name.id", "1");
        assertTrue(arguments.equals(injector.extract(query)));
    }

    @Test
    public void mutationArguments() throws Exception {
        String mutation = "mutation { createStudent (id: 1, name: \"ZAP\") }";
        HashMap<String, String> arguments = new HashMap<>();
        arguments.put("createStudent.id", "1");
        arguments.put("createStudent.name", "\"ZAP\"");
        assertTrue(arguments.equals(injector.extract(mutation)));
    }

    @Test
    public void subscriptionArguments() throws Exception {
        String subscription = "subscription { newMessage (roomId: 1) { sender text } }";
        HashMap<String, String> arguments = new HashMap<>();
        arguments.put("newMessage.roomId", "1");
        assertTrue(arguments.equals(injector.extract(subscription)));
    }

    // Injection Tests

    @Test
    public void injectOperationName() throws Exception {
        String query = "query sample { chemical (name: \"Hydrochloric Acid\") }";
        String expectedQuery = "query sample {chemical(name:\"Sulphuric Acid\")}";
        assertEquals(
                expectedQuery,
                injector.inject(query, "sample.chemical.name", "\"Sulphuric Acid\""));
    }

    @Test
    public void injectScalarArguments() throws Exception {
        String query =
                "query { polygon (sides: 1, regular: true, colour: \"blue\") { perimeter area } }";
        String expectedQuery =
                "query {polygon(sides:1,regular:false,colour:\"blue\") {perimeter area}}";
        assertEquals(expectedQuery, injector.inject(query, "polygon.regular", "false"));
    }

    @Test
    public void injectListAsArgument() throws Exception {
        String query = "query { sum (numbers: [3.14, 3.14, 3.14]) }";
        String expectedQuery = "query {sum(numbers:[0, 1, 2])}";
        assertEquals(expectedQuery, injector.inject(query, "sum.numbers", "[0, 1, 2]"));
    }

    @Test
    public void injectInputObjectArgument() throws Exception {
        String query = "query { plot (point: { x: 3.14, y: 3.14 }) }";
        String expectedQuery = "query {plot(point:{x: 1.414 , y: 1.732})}";
        assertEquals(expectedQuery, injector.inject(query, "plot.point", "{x: 1.414 , y: 1.732}"));
    }

    @Test
    public void injectInlineFragmentArguments() throws Exception {
        String query = "query { ... on field1 { name (id: 1) } }";
        String expectedQuery = "query {... on field1 {name(id:55)}}";
        assertEquals(expectedQuery, injector.inject(query, "field1.name.id", "55"));
    }

    @Test
    public void injectFragmentSpreadArguments() throws Exception {
        String query =
                "query { ...spread }  fragment spread on fragment1 {field1 { name (id: 1) } }";
        String expectedQuery =
                "query {...spread} fragment spread on fragment1 {field1 {name(id:\"ZAP\")}}";
        assertEquals(expectedQuery, injector.inject(query, "spread.field1.name.id", "\"ZAP\""));
    }

    @Test
    public void injectMutationArguments() throws Exception {
        String mutation = "mutation { createStudent (id: 1, name: \"ZAP\") }";
        String expectedMutation = "mutation {createStudent(id:42,name:\"ZAP\")}";
        assertEquals(expectedMutation, injector.inject(mutation, "createStudent.id", "42"));
    }

    @Test
    public void injectSubscriptionArguments() throws Exception {
        String subscription = "subscription { newMessage (roomId: 1) { sender text } }";
        String expectedSubscription = "subscription {newMessage(roomId:121) {sender text}}";
        assertEquals(
                expectedSubscription, injector.inject(subscription, "newMessage.roomId", "121"));
    }

    @Test
    public void injectReplaceSingleVariable() throws Exception {
        String query =
                "query ($location_direction: Direction) { location (direction: $location_direction) }";
        String expectedQuery = "query {location(direction:WEST)}";
        assertEquals(expectedQuery, injector.inject(query, "location.direction", "WEST"));
    }

    @Test
    public void injectReplaceFirstVariable() throws Exception {
        String query =
                "query ($name_height_id: ID, $name_age_id: ID, $name_id: ID) { name (id: $name_id) "
                        + "{ age (id: $name_age_id) height (id: $name_height_id) } }";
        String expectedQuery =
                "query ($name_age_id:ID, $name_id:ID) {name(id:$name_id) {age(id:$name_age_id) height(id:11)}}";
        assertEquals(expectedQuery, injector.inject(query, "name.height.id", "11"));
    }

    @Test
    public void injectReplaceMiddleVariable() throws Exception {
        String query =
                "query ($name_height_id: ID, $name_age_id: ID, $name_id: ID) { name (id: $name_id) "
                        + "{ age (id: $name_age_id) height (id: $name_height_id) } }";
        String expectedQuery =
                "query ($name_height_id:ID, $name_id:ID) {name(id:$name_id) {age(id:12) height(id:$name_height_id)}}";
        assertEquals(expectedQuery, injector.inject(query, "name.age.id", "12"));
    }

    @Test
    public void injectReplaceLastVariable() throws Exception {
        String query =
                "query ($name_height_id: ID, $name_age_id: ID, $name_id: ID) { name (id: $name_id) "
                        + "{ age (id: $name_age_id) height (id: $name_height_id) } }";
        String expectedQuery =
                "query ($name_height_id:ID, $name_age_id:ID) {name(id:13) "
                        + "{age(id:$name_age_id) height(id:$name_height_id)}}";
        assertEquals(expectedQuery, injector.inject(query, "name.id", "13"));
    }

    // Query Node Name Tests

    @Test
    public void nodeNameSimpleQuery() throws Exception {
        String query = "query { name (id: 1) }";
        String expectedQuery = "(0) query {name}";
        assertEquals(expectedQuery, injector.getNodeName(query));
    }

    @Test
    public void nodeNameNestedFields() throws Exception {
        String query = "query { name (id: 1) { age (id: 1) { height (id: 1) } } }";
        String expectedQuery = "(0) query {name {age {height}}}";
        assertEquals(expectedQuery, injector.getNodeName(query));
    }

    @Test
    public void nodeNameInputObjectArgument() throws Exception {
        String query = "query { plot (point: { x: 3.14, y: 3.14 }) }";
        String expectedQuery = "(0) query {plot}";
        assertEquals(expectedQuery, injector.getNodeName(query));
    }

    @Test
    public void nodeNameMultipleOperations() throws Exception {
        String query = "query { name (id: 1) } mutation { change_name (id: 1, name: \"ZAP\") }";
        String expectedQuery = "(00) query {name} mutation {change_name}";
        assertEquals(expectedQuery, injector.getNodeName(query));
    }

    @Test
    public void nodeNameVariables() throws Exception {
        String query = "mutation ($id: ID!, $name: String) { change_name (id: $id, name: $name) }";
        String expectedQuery = "(1) mutation {change_name}";
        assertEquals(expectedQuery, injector.getNodeName(query));
    }

    @Test
    public void nodeNameMultipleOperationsVariables() throws Exception {
        String query =
                "query ($id: ID!) { name (id: $id) } mutation ($id: ID!, $name: String) "
                        + "{ change_name (id: $id, name: $name) } subscription { newMessage (roomId: 1) { sender } }";
        String expectedQuery =
                "(110) query {name} mutation {change_name} subscription {newMessage {sender}}";
        assertEquals(expectedQuery, injector.getNodeName(query));
    }
}
