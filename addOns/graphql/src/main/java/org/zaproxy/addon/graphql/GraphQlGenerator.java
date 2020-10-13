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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.graphql.GraphQlParam.RequestMethodOption;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.model.ValueGenerator;

public class GraphQlGenerator {

    private static final Logger LOG = Logger.getLogger(GraphQlGenerator.class);
    private final Requestor requestor;
    private final GraphQlParam param;
    private GraphQLSchema schema;
    private boolean inlineArgsEnabled;

    public enum RequestType {
        QUERY,
        MUTATION,
        SUBSCRIPTION
    };

    public GraphQlGenerator(String sdl, Requestor requestor, GraphQlParam param) {
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
            StringBuilder variables = new StringBuilder();
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
            StringBuilder variables = new StringBuilder();
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
            StringBuilder variables = new StringBuilder();
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
            StringBuilder variables = new StringBuilder();
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
    private void generate(StringBuilder query, StringBuilder variables, GraphQLType type, int depth)
            throws InterruptedException {
        generate(query, variables, new StringBuilder(), type, depth, null, RequestType.QUERY);
    }

    /**
     * Generates a GraphQL query recursively
     *
     * @param query StringBuilder for the GraphQL query to be generated.
     * @param variables StringBuilder for query variables when inline arguments are disabled.
     * @param variableName StringBuilder for variable names when inline arguments are disabled.
     * @param type the type of a GraphQL field.
     * @param depth the current depth for the query being generated.
     * @param requestor Requestor for the sendByLeaf method.
     * @param requestType RequestType for the sendByLeaf method.
     */
    private void generate(
            StringBuilder query,
            StringBuilder variables,
            StringBuilder variableName,
            GraphQLType type,
            int depth,
            Requestor requestor,
            RequestType requestType)
            throws InterruptedException {
        if (type instanceof GraphQLObjectType) {
            query.append("{ ");
            GraphQLObjectType object = (GraphQLObjectType) type;
            List<GraphQLFieldDefinition> fields = object.getFieldDefinitions();
            for (GraphQLFieldDefinition field : fields) {
                if (Thread.currentThread() instanceof ParserThread) {
                    ParserThread t = (ParserThread) Thread.currentThread();
                    if (!t.isRunning()) {
                        LOG.debug("Stopping the GraphQL Generator.");
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
                        for (int i = 0; i <= depth; ++i) {
                            query.append("} ");
                        }
                        prefixRequestType(query, requestType);
                        requestor.sendQuery(
                                query.toString(), variables.toString(), param.getRequestMethod());
                    }
                } else if (depth < param.getMaxQueryDepth()) {
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

    private void addArguments(
            StringBuilder query, StringBuilder variables, GraphQLFieldDefinition field) {
        addArguments(query, variables, null, field);
    }

    private void addArguments(
            StringBuilder query,
            StringBuilder variables,
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
                        query.append(getDefaultValue(argType, 0)).append(", ");
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
                            if (!variables.toString().isEmpty()) {
                                variables.insert(
                                        1,
                                        '"'
                                                + var_name
                                                + "\": "
                                                + getDefaultValue(argType, 0)
                                                + ", ");
                            } else {
                                variables
                                        .append("{\"")
                                        .append(var_name)
                                        .append("\": ")
                                        .append(getDefaultValue(argType, 0))
                                        .append("}");
                            }
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

    private String getDefaultValue(GraphQLType type, int depth) {
        if (depth > param.getMaxArgsDepth()) return "null";
        StringBuilder defaultValue = new StringBuilder();
        if (type instanceof GraphQLNonNull) {
            GraphQLNonNull nonNullType = (GraphQLNonNull) type;
            type = nonNullType.getWrappedType();
        }
        if (type instanceof GraphQLScalarType) {
            GraphQLScalarType scalar = (GraphQLScalarType) type;
            switch (scalar.getName()) {
                case "Int":
                case "ID":
                    defaultValue.append("1");
                    break;
                case "Float":
                    defaultValue.append("3.14");
                    break;
                case "String":
                    defaultValue.append("\"ZAP\"");
                    break;
                case "Boolean":
                    defaultValue.append("true");
                    break;
            }
        } else if (type instanceof GraphQLEnumType) {
            GraphQLEnumType enumType = (GraphQLEnumType) type;
            if (inlineArgsEnabled) {
                defaultValue.append(enumType.getValues().get(0).getName());
            } else {
                defaultValue.append('"').append(enumType.getValues().get(0).getName()).append('"');
            }
        } else if (type instanceof GraphQLInputObjectType) {
            GraphQLInputObjectType object = (GraphQLInputObjectType) type;
            defaultValue.append("{ ");
            List<GraphQLInputObjectField> fields = object.getFields();
            if (inlineArgsEnabled) {
                for (GraphQLInputObjectField field : fields) {
                    defaultValue
                            .append(field.getName())
                            .append(": ")
                            .append(getDefaultValue(field.getType(), depth + 1))
                            .append(", ");
                }
            } else {
                for (GraphQLInputObjectField field : fields) {
                    defaultValue
                            .append('"')
                            .append(field.getName())
                            .append("\": ")
                            .append(getDefaultValue(field.getType(), depth + 1))
                            .append(", ");
                }
            }
            defaultValue.setLength(defaultValue.length() - 2);
            defaultValue.append(" }");
        } else if (type instanceof GraphQLList) {
            GraphQLList list = (GraphQLList) type;
            String wrappedValue = getDefaultValue(list.getWrappedType(), depth + 1);
            defaultValue
                    .append("[")
                    .append(wrappedValue)
                    .append(", ")
                    .append(wrappedValue)
                    .append(", ")
                    .append(wrappedValue)
                    .append("]");
        } else {
            defaultValue.append("null");
        }

        ValueGenerator coreValGen = null;
        try {
            coreValGen =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionSpider.class)
                            .getValueGenerator();
        } catch (NullPointerException e) {
            LOG.debug(e.getMessage());
        }

        if (coreValGen != null && type instanceof GraphQLNamedType) {
            GraphQLNamedType namedType = (GraphQLNamedType) type;
            String typeName = namedType.getName();
            HashMap<String, String> fieldAttributes = new HashMap<String, String>();
            fieldAttributes.put("Control Type", "TEXT");
            fieldAttributes.put("type", typeName);
            String value =
                    coreValGen.getValue(
                            null,
                            null,
                            typeName,
                            "",
                            Collections.<String>emptyList(),
                            Collections.<String, String>emptyMap(),
                            fieldAttributes);
            if (value != null && !value.isEmpty()) {
                return value;
            }
        }

        return defaultValue.toString();
    }
}
