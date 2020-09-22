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

import graphql.language.Argument;
import graphql.language.AstPrinter;
import graphql.language.Definition;
import graphql.language.Document;
import graphql.language.Field;
import graphql.language.FragmentDefinition;
import graphql.language.InlineFragment;
import graphql.language.OperationDefinition;
import graphql.language.Selection;
import graphql.language.Value;
import graphql.language.VariableDefinition;
import graphql.parser.Parser;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

public final class InlineInjector {

    /**
     * Extract argument names and values from a GraphQL request.
     *
     * @param query the query from which the arguments need to be extracted.
     * @return a {@link Map} that contains the name and value of all arguments in the provided
     *     query.
     */
    @SuppressWarnings("rawtypes")
    public Map<String, String> extract(String query) {
        Document document = Parser.parse(query);
        HashMap<String, String> nameValueMap = new HashMap<>();
        List<Definition> definitions = document.getDefinitions();
        for (Definition definition : definitions) {
            // For queries, mutations and subscriptions.
            if (definition instanceof OperationDefinition) {
                OperationDefinition operation = (OperationDefinition) definition;
                StringBuilder variableName = new StringBuilder();
                if (operation.getName() != null && !operation.getName().isEmpty()) {
                    variableName.append(operation.getName()).append('.');
                }
                for (Selection<?> selection : operation.getSelectionSet().getSelections()) {
                    getArguments(selection, nameValueMap, variableName);
                }
            }
            // For fragment spreads.
            else if (definition instanceof FragmentDefinition) {
                FragmentDefinition fragment = (FragmentDefinition) definition;
                StringBuilder variableName = new StringBuilder(fragment.getName()).append('.');
                for (Selection<?> selection : fragment.getSelectionSet().getSelections()) {
                    getArguments(selection, nameValueMap, variableName);
                }
            }
        }
        return nameValueMap;
    }

    private void getArguments(
            Selection<?> selection, Map<String, String> nameValueMap, StringBuilder variableName) {
        if (selection instanceof Field) {
            Field field = (Field) selection;
            variableName.append(field.getName()).append('.');
            List<Argument> args = field.getArguments();
            if (args != null && !args.isEmpty()) {
                for (Argument arg : args) {
                    String argName = variableName + arg.getName();
                    String argValue = AstPrinter.printAstCompact(arg.getValue());
                    nameValueMap.put(argName, argValue);
                }
            }
            if (field.getSelectionSet() != null) {
                for (Selection<?> subSelection : field.getSelectionSet().getSelections()) {
                    getArguments(subSelection, nameValueMap, variableName);
                }
            }
            variableName.setLength(variableName.length() - field.getName().length() - 1);
        } else if (selection instanceof InlineFragment) {
            InlineFragment inlineFragment = (InlineFragment) selection;
            variableName.append(inlineFragment.getTypeCondition().getName()).append('.');
            if (inlineFragment.getSelectionSet() != null) {
                for (Selection<?> subSelection : inlineFragment.getSelectionSet().getSelections()) {
                    getArguments(subSelection, nameValueMap, variableName);
                }
            }
            variableName.setLength(
                    variableName.length()
                            - inlineFragment.getTypeCondition().getName().length()
                            - 1);
        }
    }

    /**
     * Inject inline argument values into a GraphQL request.
     *
     * @param query the query from which the arguments need to be extracted.
     * @param name the name of the argument (must use dot notation, as in the Map returned by {@link
     *     #extract}).
     * @param value the value to be injected.
     * @return query with the injected argument value.
     */
    public String inject(String query, String name, String value) {
        Document tempDocument = Parser.parse(query);
        // Reparse with AstPrinter.printAstCompact(...) to get the right source location later.
        Document document = Parser.parse(AstPrinter.printAstCompact(tempDocument));
        StringBuilder queryBuilder = new StringBuilder(AstPrinter.printAstCompact(document));

        HashMap<String, String> nameValueMap = new HashMap<>();
        String definitionName = name.substring(0, name.indexOf('.'));

        // First check fragment spreads.
        List<FragmentDefinition> fragments =
                document.getDefinitionsOfType(FragmentDefinition.class);
        for (FragmentDefinition fragment : fragments) {
            if (definitionName.equals(fragment.getName())) {
                for (Selection<?> selection : fragment.getSelectionSet().getSelections()) {
                    setPayload(
                            queryBuilder, selection, name.substring(name.indexOf('.') + 1), value);
                }
            }
        }

        // Then check operations.
        // Checking operations later to avoid extra / unnecessary computations in some cases.
        List<OperationDefinition> operations =
                document.getDefinitionsOfType(OperationDefinition.class);
        for (OperationDefinition operation : operations) {
            if (operation.getName() != null && !operation.getName().isEmpty()) {
                if (definitionName.equals(operation.getName())) {
                    for (Selection<?> selection : operation.getSelectionSet().getSelections()) {
                        setPayload(
                                queryBuilder,
                                selection,
                                name.substring(name.indexOf('.') + 1),
                                value);
                    }
                }
            } else {
                for (Selection<?> selection : operation.getSelectionSet().getSelections()) {
                    setPayload(queryBuilder, selection, name, value);
                }
            }

            // Remove variable definition of injected argument, if it exists.
            // This will only work if the query was generated by the add-on.
            List<VariableDefinition> vars = operation.getVariableDefinitions();
            if (vars != null && !vars.isEmpty()) {
                int startPos = vars.get(0).getSourceLocation().getColumn() - 1;
                VariableDefinition endVar = vars.get(vars.size() - 1);
                int endPos =
                        endVar.getSourceLocation().getColumn()
                                + AstPrinter.printAstCompact(endVar).length()
                                - 1;

                String variableName = name.replace('.', '_');
                String csVars =
                        vars.stream()
                                .filter(var -> !variableName.equals(var.getName()))
                                .map(var -> AstPrinter.printAstCompact(var))
                                .collect(Collectors.joining(", "));
                if (csVars.isEmpty()) {
                    // Remove parantheses and extra whitespace.
                    startPos -= 2;
                    endPos++;
                }
                queryBuilder.replace(startPos, endPos, csVars);
            }
        }

        return queryBuilder.toString();
    }

    @SuppressWarnings("rawtypes")
    private void setPayload(
            StringBuilder queryBuilder, Selection<?> selection, String name, String value) {
        String selectionName = name.substring(0, name.indexOf('.'));
        if (selection instanceof Field) {
            Field field = (Field) selection;
            if (selectionName.equals(field.getName())) {
                List<Argument> args = field.getArguments();
                if (args != null && !args.isEmpty()) {
                    String argName = name.substring(name.indexOf('.') + 1);
                    if (!argName.contains(".")) {
                        for (Argument arg : args) {
                            if (argName.equals(arg.getName())) {
                                Value argValue = arg.getValue();
                                // Start Location of argument value.
                                int ivStartPos = argValue.getSourceLocation().getColumn() - 1;
                                // End Location of argument value.
                                int ivEndPos =
                                        ivStartPos + AstPrinter.printAstCompact(argValue).length();
                                queryBuilder.replace(ivStartPos, ivEndPos, value);
                                return;
                            }
                        }
                    }
                }
                if (field.getSelectionSet() != null) {
                    for (Selection<?> subSelection : field.getSelectionSet().getSelections()) {
                        setPayload(
                                queryBuilder,
                                subSelection,
                                name.substring(name.indexOf('.') + 1),
                                value);
                    }
                }
            }
        } else if (selection instanceof InlineFragment) {
            InlineFragment inlineFragment = (InlineFragment) selection;
            if (selectionName.equals(inlineFragment.getTypeCondition().getName())) {
                for (Selection<?> subSelection : inlineFragment.getSelectionSet().getSelections()) {
                    setPayload(
                            queryBuilder,
                            subSelection,
                            name.substring(name.indexOf('.') + 1),
                            value);
                }
            }
        }
    }

    /**
     * Get name of the node which represents the GraphQL message in the sites tree.
     *
     * @param query the GraphQL request.
     * @return unique node name to represent the message.
     */
    @SuppressWarnings("rawtypes")
    public String getNodeName(String query) {
        Document tempDocument = Parser.parse(query);
        // Reparse to get the right source location.
        Document document = Parser.parse(AstPrinter.printAstCompact(tempDocument));
        StringBuilder queryBuilder = new StringBuilder(AstPrinter.printAstCompact(document));
        StringBuilder queryPrefix = new StringBuilder();

        List<Definition> definitions = document.getDefinitions();
        for (int i = definitions.size() - 1; i >= 0; i--) {
            Definition definition = definitions.get(i);
            if (definition instanceof OperationDefinition) {
                OperationDefinition operation = (OperationDefinition) definition;
                List<Selection> selections = operation.getSelectionSet().getSelections();
                for (int j = selections.size() - 1; j >= 0; j--) {
                    removeArgs(queryBuilder, selections.get(j));
                }

                // Remove variable definitions.
                List<VariableDefinition> vars = operation.getVariableDefinitions();
                if (vars != null && !vars.isEmpty()) {
                    // Add '1' if it has variables.
                    queryPrefix.insert(0, 1);

                    // -1 for offset, -1 for paranthesis, -1 for whitespace.
                    int startPos = vars.get(0).getSourceLocation().getColumn() - 3;
                    VariableDefinition endVar = vars.get(vars.size() - 1);
                    int endPos =
                            endVar.getSourceLocation().getColumn()
                                    + AstPrinter.printAstCompact(endVar).length();
                    queryBuilder.replace(startPos, endPos, "");
                } else {
                    // Add '0' if it does not have variables.
                    queryPrefix.insert(0, 0);
                }
            } else if (definition instanceof FragmentDefinition) {
                FragmentDefinition fragment = (FragmentDefinition) definition;
                List<Selection> selections = fragment.getSelectionSet().getSelections();
                for (int j = selections.size() - 1; j >= 0; j--) {
                    removeArgs(queryBuilder, selections.get(j));
                }
            }
        }

        queryBuilder.insert(0, queryPrefix.insert(0, '(').append(") "));
        return queryBuilder.toString();
    }

    @SuppressWarnings("rawtypes")
    private void removeArgs(StringBuilder queryBuilder, Selection<?> selection) {
        if (selection instanceof Field) {
            Field field = (Field) selection;
            if (field.getSelectionSet() != null) {
                List<Selection> subSelections = field.getSelectionSet().getSelections();
                for (int i = subSelections.size() - 1; i >= 0; i--) {
                    removeArgs(queryBuilder, subSelections.get(i));
                }
            }
            List<Argument> args = field.getArguments();
            if (args != null && !args.isEmpty()) {
                // -1 for offset, -1 for paranthesis.
                int startPos = args.get(0).getSourceLocation().getColumn() - 2;
                Argument endArg = args.get(args.size() - 1);
                int endPos =
                        endArg.getSourceLocation().getColumn()
                                + AstPrinter.printAstCompact(endArg).length();
                queryBuilder.replace(startPos, endPos, "");
            }
        } else if (selection instanceof InlineFragment) {
            InlineFragment inlineFragment = (InlineFragment) selection;
            List<Selection> subSelections = inlineFragment.getSelectionSet().getSelections();
            for (int i = subSelections.size() - 1; i >= 0; i--) {
                removeArgs(queryBuilder, subSelections.get(i));
            }
        }
    }

    /**
     * Get operations in a GraphQL request.
     *
     * @param query the GraphQL request.
     * @return operations in the request, separated by a comma.
     */
    @SuppressWarnings("rawtypes")
    public String extractOperations(String query) {
        Document document = Parser.parse(query);
        List<Definition> definitions = document.getDefinitions();
        return definitions.stream()
                .filter(defn -> defn instanceof OperationDefinition)
                .map(defn -> (OperationDefinition) defn)
                .map(OperationDefinition::getOperation)
                .map(Object::toString)
                .map(s -> s.toLowerCase(Locale.ROOT))
                .distinct()
                .sorted()
                .collect(Collectors.joining(", "));
    }

    /**
     * Check if a GraphQL request is syntactically valid.
     *
     * @param query the GraphQL request.
     * @return true if the GraphQL request is syntactically valid.
     */
    public boolean validateQuery(String query) {
        try {
            Document document = Parser.parse(query);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
