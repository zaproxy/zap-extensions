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

import graphql.schema.GraphQLArgument;
import graphql.schema.GraphQLEnumType;
import graphql.schema.GraphQLFieldDefinition;
import graphql.schema.GraphQLInputObjectField;
import graphql.schema.GraphQLInputObjectType;
import graphql.schema.GraphQLInterfaceType;
import graphql.schema.GraphQLList;
import graphql.schema.GraphQLNamedOutputType;
import graphql.schema.GraphQLNamedType;
import graphql.schema.GraphQLNonNull;
import graphql.schema.GraphQLObjectType;
import graphql.schema.GraphQLScalarType;
import graphql.schema.GraphQLSchema;
import graphql.schema.GraphQLType;
import graphql.schema.GraphQLTypeUtil;
import graphql.schema.GraphQLUnionType;
import graphql.schema.idl.SchemaParser;
import graphql.schema.idl.UnExecutableSchemaGenerator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.addon.graphql.GraphQlParam.RequestMethodOption;

public class GraphQlGenerator {

    private static final Logger LOGGER = LogManager.getLogger(GraphQlGenerator.class);
    private final Requestor requestor;
    private final GraphQlParam param;
    private final GraphQLSchema schema;
    private boolean inlineArgsEnabled;

    public enum RequestType {
        QUERY,
        MUTATION,
        SUBSCRIPTION
    }

    private final ValueProvider valueProvider;

    public GraphQlGenerator(
            ValueProvider valueProvider, String sdl, Requestor requestor, GraphQlParam param) {
        this.valueProvider = valueProvider;
        schema = UnExecutableSchemaGenerator.makeUnExecutableSchema(new SchemaParser().parse(sdl));
        this.requestor = requestor;
        this.param = param;
    }

    /** Send three requests to check which service methods are available. */
    public void checkServiceMethods() {
        String query = "{__schema{types{name kind description}}}";
        requestor.sendQuery(query, RequestMethodOption.GET);
        requestor.sendQuery(query, RequestMethodOption.POST_JSON);
        requestor.sendQuery(query, RequestMethodOption.POST_GRAPHQL);
    }

    /** Generates and sends graphql requests based on user set parameters. */
    public void generateAndSend() {
        switch (param.getArgsType()) {
            case INLINE:
                inlineArgsEnabled = true;
                checkSplitAndSend();
                break;
            case VARIABLES:
                inlineArgsEnabled = false;
                checkSplitAndSend();
                break;
            case BOTH:
            default:
                inlineArgsEnabled = true;
                checkSplitAndSend();
                inlineArgsEnabled = false;
                checkSplitAndSend();
                break;
        }
    }

    /**
     * Generates a full graphql request with inline arguments.
     *
     * @param requestType the {@linkplain RequestType type} for which a request is generated.
     * @return the generated query / mutation / subscription or {@code null} if the generator is
     *     interrupted.
     */
    public String generate(RequestType requestType) {
        try {
            inlineArgsEnabled = true;
            StringBuilder query = new StringBuilder();
            generate(query, null, getRequestTypeObject(requestType), 0);
            prefixRequestType(query, requestType);
            return query.toString();
        } catch (InterruptedException e) {
            return null;
        }
    }

    /**
     * Generates a full graphql request with arguments using variables.
     *
     * @param requestType the {@linkplain RequestType type} for which a request is generated.
     * @return the generated query / mutation / subscription and associated variables or {@code
     *     null} if the generator is interrupted.
     */
    public String[] generateWithVariables(RequestType requestType) {
        try {
            inlineArgsEnabled = false;
            StringBuilder query = new StringBuilder();
            JSONObject variables = new JSONObject();
            generate(query, variables, getRequestTypeObject(requestType), 0);
            prefixRequestType(query, requestType);
            return new String[] {query.toString(), variables.toString()};
        } catch (InterruptedException e) {
            return null;
        }
    }

    private void checkSplitAndSend() {
        switch (param.getQuerySplitType()) {
            case OPERATION:
                sendFull(RequestType.QUERY);
                sendFull(RequestType.MUTATION);
                sendFull(RequestType.SUBSCRIPTION);
                break;
            case ROOT_FIELD:
                sendByField(RequestType.QUERY);
                sendByField(RequestType.MUTATION);
                sendByField(RequestType.SUBSCRIPTION);
                break;
            case LEAF:
            default:
                sendByLeaf(RequestType.QUERY);
                sendByLeaf(RequestType.MUTATION);
                sendByLeaf(RequestType.SUBSCRIPTION);
                break;
        }
    }

    private void sendFull(RequestType requestType) {
        try {
            StringBuilder query = new StringBuilder();
            JSONObject variables = new JSONObject();
            generate(query, variables, getRequestTypeObject(requestType), 0);
            prefixRequestType(query, requestType);
            requestor.sendQuery(query.toString(), variables.toString(), param.getRequestMethod());
        } catch (InterruptedException e) {
            // Do nothing.
        }
    }

    private void sendByLeaf(RequestType requestType) {
        try {
            StringBuilder query = new StringBuilder();
            JSONObject variables = new JSONObject();
            generate(
                    query,
                    variables,
                    new StringBuilder(),
                    getRequestTypeObject(requestType),
                    0,
                    requestor,
                    requestType);
        } catch (InterruptedException e) {
            // Do nothing.
        }
    }

    private void sendByField(RequestType requestType) {
        GraphQLObjectType object = getRequestTypeObject(requestType);
        List<GraphQLFieldDefinition> fields = object.getFieldDefinitions();
        for (GraphQLFieldDefinition field : fields) {
            StringBuilder query = new StringBuilder();
            JSONObject variables = new JSONObject();
            GraphQLType fieldType = field.getType();
            if (GraphQLTypeUtil.isWrapped(fieldType)) {
                fieldType = GraphQLTypeUtil.unwrapAll(fieldType);
            }
            query.append('{').append(field.getName()).append(' ');
            addArguments(query, variables, field);
            try {
                generate(query, variables, fieldType, 1);
            } catch (InterruptedException e) {
                return;
            }
            query.append('}');
            prefixRequestType(query, requestType);
            requestor.sendQuery(query.toString(), variables.toString(), param.getRequestMethod());
        }
    }

    private GraphQLObjectType getRequestTypeObject(RequestType requestType) {
        switch (requestType) {
            case MUTATION:
                return schema.getMutationType();
            case SUBSCRIPTION:
                return schema.getSubscriptionType();
            case QUERY:
            default:
                return schema.getQueryType();
        }
    }

    private void prefixRequestType(StringBuilder query, RequestType requestType) {
        switch (requestType) {
            case MUTATION:
                query.insert(0, "mutation ");
                break;
            case SUBSCRIPTION:
                query.insert(0, "subscription ");
                break;
            case QUERY:
            default:
                query.insert(0, "query ");
                break;
        }
    }

    /** Convenience method for generate, generateWithVariables, sendFull, and sendByField methods */
    private void generate(StringBuilder query, JSONObject variables, GraphQLType type, int depth)
            throws InterruptedException {
        generate(query, variables, new StringBuilder(), type, depth, null, RequestType.QUERY);
    }

    /**
     * Generates a GraphQL query recursively
     *
     * @param query StringBuilder for the GraphQL query to be generated.
     * @param variables StringBuilder for query variables when inline arguments are disabled.
     * @param variableName StringBuilder for variable names when inline arguments are disabled.
     * @param type the type of GraphQL field.
     * @param depth the current depth for the query being generated.
     * @param requestor Requestor for the sendByLeaf method.
     * @param requestType RequestType for the sendByLeaf method.
     */
    private void generate(
            StringBuilder query,
            JSONObject variables,
            StringBuilder variableName,
            GraphQLType type,
            int depth,
            Requestor requestor,
            RequestType requestType)
            throws InterruptedException {
        if (depth >= param.getMaxQueryDepth()) {
            if (param.getLenientMaxQueryDepthEnabled()) {
                query.append(getFirstLeafQuery(type, variables, variableName));
                if (requestor != null) {
                    query.append(StringUtils.repeat("} ", depth));
                    prefixRequestType(query, requestType);
                    requestor.sendQuery(
                            query.toString(), variables.toString(), param.getRequestMethod());
                }
            } else if (getFirstLeafField(type) == null) {
                LOGGER.warn(
                        "Potentially invalid query generated. Try enabling the Lenient Maximum Query Depth option.");
            }
        } else if (type instanceof GraphQLObjectType) {
            query.append("{ ");
            GraphQLObjectType object = (GraphQLObjectType) type;
            List<GraphQLFieldDefinition> fields = object.getFieldDefinitions();
            for (GraphQLFieldDefinition field : fields) {
                if (Thread.currentThread() instanceof ParserThread) {
                    ParserThread t = (ParserThread) Thread.currentThread();
                    if (!t.isRunning()) {
                        LOGGER.debug("Stopping the GraphQL Generator.");
                        // Break out of recursion.
                        throw new InterruptedException();
                    }
                }
                GraphQLType fieldType = field.getType();
                String beforeSendingByLeaf = query.toString();
                if (GraphQLTypeUtil.isWrapped(fieldType)) {
                    fieldType = GraphQLTypeUtil.unwrapAll(fieldType);
                }
                if (GraphQLTypeUtil.isLeaf(fieldType)) {
                    query.append(field.getName()).append(' ');
                    variableName.append(field.getName()).append('_');
                    addArguments(query, variables, variableName, field);
                    variableName.setLength(variableName.length() - field.getName().length() - 1);
                    if (requestor != null) {
                        query.append("} ".repeat(depth + 1));
                        prefixRequestType(query, requestType);
                        requestor.sendQuery(
                                query.toString(), variables.toString(), param.getRequestMethod());
                    }
                } else {
                    query.append(field.getName()).append(' ');
                    variableName.append(field.getName()).append('_');
                    addArguments(query, variables, variableName, field);
                    generate(
                            query,
                            variables,
                            variableName,
                            fieldType,
                            depth + 1,
                            requestor,
                            requestType);
                    variableName.setLength(variableName.length() - field.getName().length() - 1);
                }
                if (requestor != null) {
                    query = new StringBuilder(beforeSendingByLeaf);
                }
            }
            query.append("} ");
        } else if (type instanceof GraphQLInterfaceType) {
            List<GraphQLObjectType> objects =
                    schema.getImplementations((GraphQLInterfaceType) type);
            query.append("{ ");
            for (GraphQLObjectType object : objects) {
                query.append("... on ").append(object.getName()).append(' ');
                generate(query, variables, variableName, object, depth + 1, requestor, requestType);
            }
            query.append("} ");
        } else if (type instanceof GraphQLUnionType) {
            GraphQLUnionType union = (GraphQLUnionType) type;
            List<GraphQLNamedOutputType> members = union.getTypes();
            query.append("{ ");
            for (GraphQLNamedOutputType member : members) {
                query.append("... on ").append(member.getName()).append(' ');
                generate(query, variables, variableName, member, depth + 1, requestor, requestType);
            }
            query.append("} ");
        }
    }

    /**
     * Does a breadth-first search for a leaf type and generates a query that has the leaf type as
     * its deepest node.
     *
     * @param type the root {@link GraphQLType} node.
     * @param variables query variables passed on to {@link #addArguments}.
     * @param variableName StringBuilder used for variable names.
     * @return the generated query
     */
    String getFirstLeafQuery(GraphQLType type, JSONObject variables, StringBuilder variableName) {

        class Node {
            final GraphQLType graphQLType;
            final StringBuilder query;
            final StringBuilder variableName;
            final JSONObject variables;

            Node(
                    GraphQLType graphQLType,
                    StringBuilder query,
                    JSONObject variables,
                    StringBuilder variableName) {
                this.graphQLType = graphQLType;
                this.query = query;
                this.variables = variables;
                this.variableName = variableName;
            }

            Node(GraphQLType graphQLType, Node parent) {
                this.graphQLType = graphQLType;
                query = new StringBuilder(parent.getQuery());
                variables = JSONObject.fromObject(parent.getVariables());
                variableName = new StringBuilder(parent.getVariableName());
            }

            public GraphQLType getType() {
                return graphQLType;
            }

            public StringBuilder getQuery() {
                return query;
            }

            public JSONObject getVariables() {
                return variables;
            }

            public StringBuilder getVariableName() {
                return variableName;
            }
        }

        List<Node> parentList = new ArrayList<>();
        parentList.add(
                new Node(
                        type,
                        new StringBuilder("{ "),
                        variables != null ? variables : new JSONObject(),
                        variableName != null ? variableName : new StringBuilder()));
        for (int depth = 0; depth < param.getMaxAdditionalQueryDepth(); ++depth) {
            List<Node> childrenList = new ArrayList<>();
            for (Node parent : parentList) {
                GraphQLFieldDefinition leafField = getFirstLeafField(parent.getType());
                if (leafField != null) {
                    Node leaf = new Node(leafField.getType(), parent);
                    leaf.getQuery().append(leafField.getName()).append(' ');
                    leaf.getVariableName().append(leafField.getName()).append('_');
                    addArguments(
                            leaf.getQuery(),
                            leaf.getVariables(),
                            leaf.getVariableName(),
                            leafField);
                    leaf.getQuery()
                            .append(
                                    StringUtils.repeat(
                                            "} ",
                                            StringUtils.countMatches(
                                                    leaf.getQuery().toString(), '{')));
                    if (variables != null) {
                        variables.clear();
                        variables.putAll(leaf.getVariables());
                    }
                    return leaf.getQuery().toString();
                }

                if (parent.getType() instanceof GraphQLObjectType) {
                    GraphQLObjectType object = (GraphQLObjectType) parent.getType();
                    List<GraphQLFieldDefinition> fieldList = object.getFieldDefinitions();

                    for (GraphQLFieldDefinition field : fieldList) {
                        Node child = new Node(field.getType(), parent);
                        child.getQuery().append(field.getName()).append(' ');
                        child.getVariableName().append(field.getName()).append('_');
                        addArguments(
                                child.getQuery(),
                                child.getVariables(),
                                child.getVariableName(),
                                field);
                        child.getQuery().append("{ ");
                        childrenList.add(child);
                    }
                } else if (parent.getType() instanceof GraphQLInterfaceType) {
                    List<GraphQLObjectType> implementations =
                            schema.getImplementations((GraphQLInterfaceType) parent.getType());
                    for (GraphQLObjectType imp : implementations) {
                        Node child = new Node(imp, parent);
                        child.getQuery().append("... on ").append(imp.getName()).append(" { ");
                        child.getVariableName().append(imp.getName()).append('_');
                        childrenList.add(child);
                    }
                } else if (parent.getType() instanceof GraphQLUnionType) {
                    GraphQLUnionType union = (GraphQLUnionType) parent.getType();
                    List<GraphQLNamedOutputType> membersList = union.getTypes();
                    for (GraphQLNamedOutputType member : membersList) {
                        Node child = new Node(member, parent);
                        child.getQuery().append("... on ").append(member.getName()).append(" { ");
                        child.getVariableName().append(member.getName()).append('_');
                        childrenList.add(child);
                    }
                }
            }
            parentList = childrenList;
        }
        LOGGER.warn(
                "Potentially invalid query generated. Try increasing the Additional Query Depth value.");
        return "";
    }

    private GraphQLFieldDefinition getFirstLeafField(GraphQLType type) {
        type = GraphQLTypeUtil.unwrapAll(type);
        if (type instanceof GraphQLObjectType) {
            GraphQLObjectType object = (GraphQLObjectType) type;
            return object.getFieldDefinitions().stream()
                    .filter(f -> GraphQLTypeUtil.isLeaf(GraphQLTypeUtil.unwrapAll(f.getType())))
                    .findFirst()
                    .orElse(null);
        }
        // Union and Interface types cannot have leaf fields as members or implementors.
        return null;
    }

    private void addArguments(
            StringBuilder query, JSONObject variables, GraphQLFieldDefinition field) {
        addArguments(query, variables, null, field);
    }

    private void addArguments(
            StringBuilder query,
            JSONObject variables,
            StringBuilder variableName,
            GraphQLFieldDefinition field) {
        List<GraphQLArgument> args = field.getArguments();
        if (args != null && !args.isEmpty()) {
            query.append('(');
            boolean nonZeroArguments = false;
            for (GraphQLArgument arg : args) {
                GraphQLType argType = arg.getType();
                if (param.getOptionalArgsEnabled() || GraphQLTypeUtil.isNonNull(argType)) {
                    query.append(arg.getName()).append(": ");
                    if (inlineArgsEnabled) {
                        query.append(getDefaultValue(arg.getName(), argType, 0, true)).append(", ");
                    } else {
                        String var_name;
                        if (variableName != null) {
                            var_name = variableName + arg.getName();
                        } else {
                            // Only for the root fields in sendByField.
                            var_name = field.getName() + '_' + arg.getName();
                        }
                        query.append('$').append(var_name).append(", ");

                        String var_type = "";
                        if (GraphQLTypeUtil.isWrapped(argType)) {
                            var_type = argType.toString();
                        } else if (argType instanceof GraphQLNamedType) {
                            GraphQLNamedType namedType = (GraphQLNamedType) argType;
                            var_type = namedType.getName();
                        }
                        if (var_type != null && !var_type.isEmpty()) {
                            if (query.toString().startsWith("(")) {
                                query.insert(1, '$' + var_name + ": " + var_type + ", ");
                            } else {
                                query.insert(0, "($" + var_name + ": " + var_type + ") ");
                            }
                        }

                        if (variables != null) {
                            variables.put(
                                    var_name, getDefaultValue(arg.getName(), argType, 0, false));
                        }
                    }
                    nonZeroArguments = true;
                }
            }
            if (nonZeroArguments) {
                query.setLength(query.length() - 2);
                query.append(") ");
            } else {
                query.setLength(query.length() - 1);
            }
        }
    }

    private Object getDefaultValue(
            String argName, GraphQLType type, int depth, boolean quoteStrings) {
        if (depth > param.getMaxArgsDepth()) return null;

        if (type instanceof GraphQLNonNull) {
            GraphQLNonNull nonNullType = (GraphQLNonNull) type;
            type = nonNullType.getWrappedType();
        }

        HashMap<String, String> fieldAttributes = new HashMap<>();
        fieldAttributes.put("Control Type", "TEXT");
        fieldAttributes.put("type", argName);
        String value =
                valueProvider.getValue(
                        null,
                        null,
                        argName,
                        "",
                        Collections.emptyList(),
                        Collections.emptyMap(),
                        fieldAttributes);
        if (value != null && !value.isEmpty()) {
            if (quoteStrings
                    && type instanceof GraphQLScalarType
                    && "String".equals(((GraphQLScalarType) type).getName())) {
                return '"' + value + '"';
            }
            return value;
        }

        if (type instanceof GraphQLScalarType) {
            GraphQLScalarType scalar = (GraphQLScalarType) type;
            switch (scalar.getName()) {
                case "Int":
                case "ID":
                    return 1;
                case "Float":
                    return 3.14;
                case "String":
                    return quoteStrings ? "\"ZAP\"" : "ZAP";
                case "Boolean":
                    return true;
                default:
                    return null;
            }
        } else if (type instanceof GraphQLEnumType) {
            GraphQLEnumType enumType = (GraphQLEnumType) type;
            return enumType.getValues().get(0).getName();
        } else if (type instanceof GraphQLInputObjectType) {
            GraphQLInputObjectType object = (GraphQLInputObjectType) type;
            List<GraphQLInputObjectField> fields = object.getFields();
            if (inlineArgsEnabled) {
                StringBuilder defaultValue = new StringBuilder();
                defaultValue.append("{ ");
                for (GraphQLInputObjectField field : fields) {
                    defaultValue
                            .append(field.getName())
                            .append(": ")
                            .append(
                                    getDefaultValue(
                                            field.getName(),
                                            field.getType(),
                                            depth + 1,
                                            quoteStrings))
                            .append(", ");
                }
                defaultValue.setLength(defaultValue.length() - 2);
                defaultValue.append(" }");
                return defaultValue.toString();
            } else {
                JSONObject defaultValue = new JSONObject();
                for (GraphQLInputObjectField field : fields) {
                    defaultValue.put(
                            field.getName(),
                            getDefaultValue(
                                    field.getName(), field.getType(), depth + 1, quoteStrings));
                }
                return defaultValue;
            }
        } else if (type instanceof GraphQLList) {
            GraphQLList list = (GraphQLList) type;
            if (inlineArgsEnabled) {
                Object wrappedValue = getDefaultValue(null, list.getWrappedType(), depth + 1, true);
                return "[" + wrappedValue + ", " + wrappedValue + ", " + wrappedValue + ']';
            } else {
                JSONArray defaultValue = new JSONArray();
                Object wrappedValue =
                        getDefaultValue(null, list.getWrappedType(), depth + 1, false);
                defaultValue.add(wrappedValue);
                defaultValue.add(wrappedValue);
                defaultValue.add(wrappedValue);
                return defaultValue;
            }
        } else {
            return null;
        }
    }
}
