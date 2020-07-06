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
    private static final String OPERATION_TYPE_MUTATION = "mutation ";
    private static final String OPERATION_TYPE_SUBSCRIPTION = "subscription ";
    private final Requestor requestor;
    private final GraphQlParam param;
    private GraphQLSchema schema;

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

    public void checkServiceMethods() {
        String query = "{__schema{types{name kind description}}}";
        requestor.sendQuery(query, RequestMethodOption.GET);
        requestor.sendQuery(query, RequestMethodOption.POST_JSON);
        requestor.sendQuery(query, RequestMethodOption.POST_GRAPHQL);
    }

    public String generateFull(RequestType requestType) {
        StringBuilder query = new StringBuilder();
        GraphQLObjectType object;
        switch (requestType) {
            case MUTATION:
                query.append(OPERATION_TYPE_MUTATION);
                object = schema.getMutationType();
                break;
            case SUBSCRIPTION:
                query.append(OPERATION_TYPE_SUBSCRIPTION);
                object = schema.getSubscriptionType();
                break;
            case QUERY:
            default:
                object = schema.getQueryType();
                break;
        }
        generate(query, object, 0);
        return query.toString();
    }

    public void sendFull(RequestType requestType) {
        switch (requestType) {
            case MUTATION:
                StringBuilder mutation = new StringBuilder(OPERATION_TYPE_MUTATION);
                generate(mutation, schema.getMutationType(), 0);
                requestor.sendQuery(mutation.toString(), param.getRequestMethod());
                break;
            case SUBSCRIPTION:
                StringBuilder subscription = new StringBuilder(OPERATION_TYPE_SUBSCRIPTION);
                generate(subscription, schema.getSubscriptionType(), 0);
                requestor.sendQuery(subscription.toString(), param.getRequestMethod());
                break;
            case QUERY:
            default:
                StringBuilder query = new StringBuilder();
                generate(query, schema.getQueryType(), 0);
                requestor.sendQuery(query.toString(), param.getRequestMethod());
                break;
        }
    }

    public void sendByLeaf(RequestType requestType) {
        switch (requestType) {
            case MUTATION:
                StringBuilder mutation = new StringBuilder();
                generate(mutation, schema.getMutationType(), 0, requestor);
                break;
            case SUBSCRIPTION:
                StringBuilder subscription = new StringBuilder();
                generate(subscription, schema.getSubscriptionType(), 0, requestor);
                break;
            case QUERY:
            default:
                StringBuilder query = new StringBuilder();
                generate(query, schema.getQueryType(), 0, requestor);
                break;
        }
    }

    public void sendByField(RequestType requestType) {
        GraphQLObjectType object;
        switch (requestType) {
            case MUTATION:
                object = schema.getMutationType();
                break;
            case SUBSCRIPTION:
                object = schema.getSubscriptionType();
                break;
            case QUERY:
            default:
                object = schema.getQueryType();
                break;
        }
        List<GraphQLFieldDefinition> fields = object.getFieldDefinitions();
        for (GraphQLFieldDefinition field : fields) {
            StringBuilder query = new StringBuilder();
            generate(query, field.getType(), 1);
            requestor.sendQuery(query.toString(), param.getRequestMethod());
        }
    }

    private void generate(StringBuilder query, GraphQLType type, int depth) {
        generate(query, type, depth, null);
    }

    private void generate(StringBuilder query, GraphQLType type, int depth, Requestor requestor) {
        if (type instanceof GraphQLObjectType) {
            query.append("{ ");
            GraphQLObjectType object = (GraphQLObjectType) type;
            List<GraphQLFieldDefinition> fields = object.getFieldDefinitions();
            for (GraphQLFieldDefinition field : fields) {
                GraphQLType fieldType = field.getType();
                int parentLength = query.length();
                if (GraphQLTypeUtil.isWrapped(fieldType)) {
                    fieldType = GraphQLTypeUtil.unwrapAll(fieldType);
                }
                if (GraphQLTypeUtil.isLeaf(fieldType)) {
                    query.append(field.getName()).append(' ');
                    addArguments(query, field);
                    if (requestor != null) {
                        for (int i = 0; i <= depth; ++i) {
                            query.append("} ");
                        }
                        requestor.sendQuery(query.toString(), param.getRequestMethod());
                    }
                } else if (depth < param.getMaxQueryDepth()) {
                    query.append(field.getName()).append(' ');
                    addArguments(query, field);
                    generate(query, fieldType, depth + 1, requestor);
                }
                if (requestor != null) {
                    query.setLength(parentLength);
                }
            }
            query.append("} ");
        } else if (type instanceof GraphQLInterfaceType) {
            List<GraphQLObjectType> objects =
                    schema.getImplementations((GraphQLInterfaceType) type);
            query.append("{ ");
            for (GraphQLObjectType object : objects) {
                query.append("... on ").append(object.getName()).append(' ');
                generate(query, object, depth + 1, requestor);
            }
            query.append("} ");
        } else if (type instanceof GraphQLUnionType) {
            GraphQLUnionType union = (GraphQLUnionType) type;
            List<GraphQLNamedOutputType> members = union.getTypes();
            query.append("{ ");
            for (GraphQLNamedOutputType member : members) {
                query.append("... on ").append(member.getName()).append(' ');
                generate(query, member, depth + 1, requestor);
            }
            query.append("} ");
        }
    }

    private void addArguments(StringBuilder query, GraphQLFieldDefinition field) {
        List<GraphQLArgument> args = field.getArguments();
        if (!args.isEmpty()) {
            query.append('(');
            boolean nonZeroArguments = false;
            for (GraphQLArgument arg : args) {
                if (param.getOptionalArgsEnabled() || GraphQLTypeUtil.isNonNull(arg.getType())) {
                    query.append(arg.getName())
                            .append(": ")
                            .append(getDefaultValue(arg.getType(), 0))
                            .append(", ");
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
            defaultValue.append(enumType.getValues().get(0).getName());
        } else if (type instanceof GraphQLInputObjectType) {
            GraphQLInputObjectType object = (GraphQLInputObjectType) type;
            defaultValue.append("{ ");
            List<GraphQLInputObjectField> fields = object.getFields();
            for (GraphQLInputObjectField field : fields) {
                defaultValue
                        .append(field.getName())
                        .append(": ")
                        .append(getDefaultValue(field.getType(), depth + 1))
                        .append(", ");
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
            if (!value.isEmpty()) {
                return value;
            }
        }

        return defaultValue.toString();
    }
}
