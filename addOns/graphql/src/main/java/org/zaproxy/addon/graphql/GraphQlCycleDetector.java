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
package org.zaproxy.addon.graphql;

import graphql.schema.GraphQLFieldDefinition;
import graphql.schema.GraphQLObjectType;
import graphql.schema.GraphQLSchema;
import graphql.schema.GraphQLType;
import graphql.schema.GraphQLTypeUtil;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.alert.ExtensionAlert;

public class GraphQlCycleDetector {

    private static final Logger LOGGER = LogManager.getLogger(GraphQlCycleDetector.class);
    private static final String CYCLES_ALERT_REF = ExtensionGraphQl.TOOL_ALERT_ID + "-3";
    private static final Map<String, String> CYCLES_ALERT_TAGS =
            CommonAlertTag.mergeTags(
                    Map.of(
                            "OWASP_2023_API4",
                            "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"),
                    CommonAlertTag.OWASP_2021_A04_INSECURE_DESIGN,
                    CommonAlertTag.WSTG_V42_APIT_01_GRAPHQL);
    private static final CycleDetectionCompleteException CYCLE_DETECTION_COMPLETE_EXCEPTION =
            new CycleDetectionCompleteException();

    private final GraphQLSchema schema;
    private final GraphQlGenerator generator;
    private final GraphQlQueryMessageBuilder queryMsgBuilder;
    private final GraphQlParam param;
    private final Map<GraphQLObjectType, Node> typeNodeMap;

    public GraphQlCycleDetector(
            GraphQLSchema schema,
            GraphQlGenerator generator,
            GraphQlQueryMessageBuilder queryMsgBuilder,
            GraphQlParam param) {
        this.schema = schema;
        this.generator = generator;
        this.queryMsgBuilder = queryMsgBuilder;
        this.param = param;
        this.typeNodeMap = buildTypeGraph(schema);
    }

    public void detectCycles() {
        if (param.getCycleDetectionMode() == GraphQlParam.CycleDetectionModeOption.DISABLED
                || param.getMaxCycleDetectionAlerts() == 0) {
            return;
        }
        AtomicInteger cycleCount = new AtomicInteger();
        try {
            detectCycles(
                    result -> {
                        raiseAlert(result);
                        if (cycleCount.incrementAndGet() >= param.getMaxCycleDetectionAlerts()) {
                            throw CYCLE_DETECTION_COMPLETE_EXCEPTION;
                        }
                    });
        } catch (CycleDetectionCompleteException ignored) {
        }
    }

    void detectCycles(Consumer<GraphQlCycleDetectionResult> cycleResultConsumer) {
        List<Node> allNodes =
                typeNodeMap.values().stream()
                        .sorted(Comparator.comparingInt(node -> node.neighbors.size()))
                        .toList();
        List<SCC> currentSCCs = findStronglyConnectedComponents(allNodes);
        Consumer<Cycle> cycleConsumer =
                cycle -> buildCycleDetectionResult(cycle).ifPresent(cycleResultConsumer);
        for (int i = 0; i < allNodes.size(); i++) {
            Node startNode = allNodes.get(i);

            if (currentSCCs.stream()
                    .noneMatch(scc -> scc.nodes.contains(startNode) && scc.nodes.size() > 1)) {
                continue;
            }

            findCyclesInSCC(startNode, cycleConsumer);

            for (int j = i + 1; j < allNodes.size(); j++) {
                Node node = allNodes.get(j);
                node.index = -1;
                node.lowLink = -1;
                node.onStack = false;
                node.neighbors.remove(startNode);
            }

            currentSCCs = findStronglyConnectedComponents(allNodes.subList(i + 1, allNodes.size()));
        }
    }

    private static Map<GraphQLObjectType, Node> buildTypeGraph(GraphQLSchema schema) {
        // Create a node for each object type and add it to the graph
        Map<GraphQLObjectType, Node> graph =
                schema.getAllTypesAsList().stream()
                        .filter(type -> !type.getName().startsWith("__")) // Ignore reserved types
                        .filter(GraphQLObjectType.class::isInstance)
                        .map(GraphQLObjectType.class::cast)
                        .collect(Collectors.toUnmodifiableMap(Function.identity(), Node::new));
        // Draw edges between nodes
        for (Map.Entry<GraphQLObjectType, Node> sourceEntry : graph.entrySet()) {
            for (GraphQLFieldDefinition field : sourceEntry.getKey().getFieldDefinitions()) {
                GraphQLType fieldType = GraphQLTypeUtil.unwrapAll(field.getType());
                if (fieldType instanceof GraphQLObjectType targetType
                        && graph.containsKey(targetType)) {
                    sourceEntry.getValue().neighbors.add(graph.get(targetType));
                }
            }
        }
        return graph;
    }

    private List<SCC> findStronglyConnectedComponents(List<Node> nodes) {
        // Use Tarjan's algorithm to find strongly connected components in the graph, ref:
        // https://en.wikipedia.org/wiki/Tarjan%27s_strongly_connected_components_algorithm
        List<SCC> sccs = new ArrayList<>();
        Deque<Node> stack = new ArrayDeque<>();
        AtomicInteger index = new AtomicInteger(0);
        for (Node node : nodes) {
            if (node.index == -1) {
                strongConnect(node, stack, index, sccs);
            }
        }
        return sccs;
    }

    private void strongConnect(Node node, Deque<Node> stack, AtomicInteger index, List<SCC> sccs) {
        node.index = index.get();
        node.lowLink = index.get();
        index.incrementAndGet();
        stack.push(node);
        node.onStack = true;

        for (Node neighbor : node.neighbors) {
            if (neighbor.index == -1) {
                strongConnect(neighbor, stack, index, sccs);
                node.lowLink = Math.min(node.lowLink, neighbor.lowLink);
            } else if (neighbor.onStack) {
                node.lowLink = Math.min(node.lowLink, neighbor.index);
            }
        }

        if (node.lowLink == node.index) {
            List<Node> sccNodes = new ArrayList<>();
            Node w;
            do {
                w = stack.pop();
                w.onStack = false;
                sccNodes.add(0, w);
            } while (w != node);

            if (sccNodes.size() > 1) {
                sccs.add(new SCC(sccNodes));
            }
        }
    }

    private void findCyclesInSCC(Node startNode, Consumer<Cycle> cycleConsumer) {
        // Use Johnson's algorithm to find cycles in a strongly connected component, ref:
        // https://github.com/mission-peace/interview/blob/master/src/com/interview/graph/AllCyclesInDirectedGraphJohnson.java
        Set<Node> blockedNodes = new HashSet<>();
        Map<Node, Set<Node>> unblockDependencies = new HashMap<>();
        Deque<Node> stack = new ArrayDeque<>();
        findCyclesFromNode(
                startNode, startNode, blockedNodes, unblockDependencies, stack, cycleConsumer);
    }

    private boolean findCyclesFromNode(
            Node currentNode,
            Node startNode,
            Set<Node> blockedNodes,
            Map<Node, Set<Node>> unblockDependencies,
            Deque<Node> stack,
            Consumer<Cycle> cycleConsumer) {
        boolean foundCycle = false;
        stack.push(currentNode);
        blockedNodes.add(currentNode);
        for (Node neighbor : currentNode.neighbors) {
            if (neighbor == startNode) {
                // Found a cycle
                cycleConsumer.accept(new Cycle(new ArrayList<>(stack)));
                foundCycle = true;
                if (param.getCycleDetectionMode() == GraphQlParam.CycleDetectionModeOption.QUICK) {
                    return true;
                }
            } else if (!blockedNodes.contains(neighbor)) {
                foundCycle |=
                        findCyclesFromNode(
                                neighbor,
                                startNode,
                                blockedNodes,
                                unblockDependencies,
                                stack,
                                cycleConsumer);
            }
        }
        if (foundCycle) {
            unblockNodeAndDependents(currentNode, blockedNodes, unblockDependencies);
        } else {
            for (Node neighbor : currentNode.neighbors) {
                unblockDependencies
                        .computeIfAbsent(neighbor, k -> new HashSet<>())
                        .add(currentNode);
            }
        }
        stack.pop();
        return foundCycle;
    }

    private void unblockNodeAndDependents(
            Node nodeToUnblock, Set<Node> blockedNodes, Map<Node, Set<Node>> unblockDependencies) {
        blockedNodes.remove(nodeToUnblock);
        if (unblockDependencies.containsKey(nodeToUnblock)) {
            unblockDependencies
                    .get(nodeToUnblock)
                    .forEach(
                            node -> {
                                if (blockedNodes.contains(node)) {
                                    unblockNodeAndDependents(
                                            node, blockedNodes, unblockDependencies);
                                }
                            });
            unblockDependencies.remove(nodeToUnblock);
        }
    }

    private List<Node> findShortestPathToCycle(Cycle cycle) {
        Set<Node> cycleNodes = new HashSet<>(cycle.nodes);
        Queue<PathInfo> queue = new LinkedList<>();
        Set<Node> visited = new HashSet<>();

        addRootTypesToQueue(queue, visited);

        while (!queue.isEmpty()) {
            PathInfo current = queue.poll();
            Node currentNode = current.path.get(current.path.size() - 1);

            if (cycleNodes.contains(currentNode)) {
                return current.path;
            }

            for (Node neighbor : currentNode.neighbors) {
                if (!visited.contains(neighbor)) {
                    visited.add(neighbor);
                    List<Node> newPath = new ArrayList<>(current.path);
                    newPath.add(neighbor);
                    queue.offer(new PathInfo(newPath, current.distance + 1));
                }
            }
        }

        LOGGER.debug(
                "No path found to cycle: {}",
                cycle.nodes.stream().map(node -> node.type.getName()).toList());
        return List.of();
    }

    private void addRootTypesToQueue(Queue<PathInfo> queue, Set<Node> visited) {
        if (schema.getQueryType() != null) {
            Node queryNode = typeNodeMap.get(schema.getQueryType());
            queue.offer(new PathInfo(List.of(queryNode), 0));
            visited.add(queryNode);
        }
        if (schema.getMutationType() != null) {
            Node mutationNode = typeNodeMap.get(schema.getMutationType());
            queue.offer(new PathInfo(List.of(mutationNode), 0));
            visited.add(mutationNode);
        }
        if (schema.getSubscriptionType() != null) {
            Node subscriptionNode = typeNodeMap.get(schema.getSubscriptionType());
            queue.offer(new PathInfo(List.of(subscriptionNode), 0));
            visited.add(subscriptionNode);
        }
    }

    private Optional<GraphQlCycleDetectionResult> buildCycleDetectionResult(Cycle cycle) {
        List<Node> pathToCycle = findShortestPathToCycle(cycle);
        if (pathToCycle.isEmpty()) {
            LOGGER.debug("Path to cycle not found: {}", cycle);
            return Optional.empty();
        }
        Node intersectionNode = pathToCycle.get(pathToCycle.size() - 1);
        int cycleStartIndex = cycle.nodes.indexOf(intersectionNode);
        if (cycleStartIndex == -1) {
            LOGGER.debug("Path doesn't properly connect to cycle: {}", cycle);
            return Optional.empty();
        }
        List<Node> fullPath = new ArrayList<>(pathToCycle.subList(0, pathToCycle.size() - 1));
        for (int i = 0; i < cycle.nodes.size(); i++) {
            int index = (i + cycleStartIndex) % cycle.nodes.size();
            fullPath.add(cycle.nodes.get(index));
        }
        fullPath.add(intersectionNode);
        String typeChain =
                String.join(
                                        " -> ",
                                        fullPath.stream()
                                                .map(node -> node.type)
                                                .map(GraphQLObjectType::getName)
                                                .toList())
                                .replaceFirst(
                                        intersectionNode.type.getName(),
                                        "(" + intersectionNode.type.getName())
                        + ")";

        var query = new StringBuilder("{ ");
        var variables = new JSONObject();
        for (int i = 0; i < fullPath.size() - 1; i++) {
            Node node = fullPath.get(i);
            Node nextNode = fullPath.get(i + 1);
            Optional<GraphQLFieldDefinition> field =
                    node.type.getFieldDefinitions().stream()
                            .filter(
                                    f ->
                                            GraphQLTypeUtil.unwrapAll(f.getType())
                                                    .equals(nextNode.type))
                            .findAny();
            if (field.isEmpty()) {
                LOGGER.debug(
                        "{} missing in field definitions of {}",
                        nextNode.type.getName(),
                        node.type.getName());
                return Optional.empty();
            }
            query.append(field.get().getName()).append(" ");
            generator.addArguments(query, variables, field.get());
            query.append("{ ");
        }
        query.setLength(query.length() - 2); // Remove trailing "{ "
        query.append(generator.getFirstLeafQuery(intersectionNode.type, variables, null));
        query.append(
                StringUtils.repeat(
                        "} ",
                        StringUtils.countMatches(query, "{")
                                - StringUtils.countMatches(query, "}")));
        query.setLength(query.length() - 1); // Remove trailing space
        GraphQLType rootType = fullPath.get(0).type;
        if (rootType.equals(schema.getQueryType())) {
            query.insert(0, "query ");
        } else if (rootType.equals(schema.getMutationType())) {
            query.insert(0, "mutation ");
        } else if (rootType.equals(schema.getSubscriptionType())) {
            query.insert(0, "subscription ");
        }
        return Optional.of(
                new GraphQlCycleDetectionResult(typeChain, query.toString(), variables.toString()));
    }

    private void raiseAlert(GraphQlCycleDetectionResult result) {
        var extAlert =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
        if (extAlert == null) {
            return;
        }
        try {
            Alert alert =
                    getBaseAlertBuilder()
                            .setOtherInfo(result.cycle)
                            .setMessage(
                                    queryMsgBuilder.buildQueryMessage(
                                            result.query,
                                            result.variables,
                                            param.getRequestMethod()))
                            .build();
            extAlert.alertFound(alert, null);
        } catch (Exception e) {
            LOGGER.error("Failed to build alert for GraphQL cycle", e);
        }
    }

    private static Alert.Builder getBaseAlertBuilder() {
        return Alert.builder()
                .setPluginId(ExtensionGraphQl.TOOL_ALERT_ID)
                .setAlertRef(CYCLES_ALERT_REF)
                .setName(Constant.messages.getString("graphql.cycles.alert.name"))
                .setDescription(Constant.messages.getString("graphql.cycles.alert.desc"))
                .setReference(Constant.messages.getString("graphql.cycles.alert.ref"))
                .setSolution(Constant.messages.getString("graphql.cycles.alert.soln"))
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setRisk(Alert.RISK_INFO)
                .setCweId(16)
                .setWascId(15)
                .setSource(Alert.Source.TOOL)
                .setTags(CYCLES_ALERT_TAGS);
    }

    static Alert getExampleAlert() {
        return getBaseAlertBuilder()
                .setOtherInfo(
                        "Query -> (Organization -> Repository -> PullRequest -> Commit -> Organization)")
                .build();
    }

    record GraphQlCycleDetectionResult(String cycle, String query, String variables) {}

    @RequiredArgsConstructor
    private static class Node {
        final GraphQLObjectType type;
        int index = -1;
        int lowLink = -1;
        boolean onStack = false;
        Set<Node> neighbors = new HashSet<>();
    }

    private record SCC(List<Node> nodes) {
        // SCC stands for "Strongly Connected Component".
        // Ref: https://en.wikipedia.org/wiki/Strongly_connected_component
    }

    private record PathInfo(List<Node> path, int distance) {}

    private record Cycle(List<Node> nodes) {
        @Override
        public String toString() {
            return nodes.stream()
                    .map(node -> node.type.getName())
                    .collect(Collectors.joining(" -> "));
        }
    }

    private static class CycleDetectionCompleteException extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }
}
