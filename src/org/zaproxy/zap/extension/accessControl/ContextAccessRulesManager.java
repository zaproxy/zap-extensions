/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2014 The ZAP Development Team.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.accessControl;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.model.Session;
import org.zaproxy.zap.extension.accessControl.widgets.ContextSiteTree;
import org.zaproxy.zap.extension.accessControl.widgets.SiteTreeNode;
import org.zaproxy.zap.extension.accessControl.widgets.UriUtils;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;

/**
 * An object that manages the access rules that have been configured for a {@link Context}.
 * 
 * Note: In order to store access rules for unauthenticated visitors, we'll use
 * {@link #UNAUTHENTICATED_USER_ID} as the id, which is an id that should not be generated for
 * normal users.
 * 
 * @author cosminstefanxp
 */
public class ContextAccessRulesManager {

	private static final Logger log = Logger.getLogger(ContextAccessRulesManager.class);
	/**
	 * In order to store access rules for unauthenticated visitors, we'll use -1 as the id, which is
	 * an id that should not be generated for normal users.
	 */
	public static final int UNAUTHENTICATED_USER_ID = -1;
	/**
	 * The separator used during the serialization of the rules.
	 */
	private static final char SERIALIZATION_SEPARATOR = '`';

	private Context context;
	private Map<Integer, Map<SiteTreeNode, AccessRule>> rules;
	private ContextSiteTree contextSiteTree;

	public ContextAccessRulesManager(Context context) {
		this.context = context;
		this.rules = new HashMap<>();
		this.contextSiteTree = new ContextSiteTree();
	}

	/**
	 * Instantiates a new context access rules manager by performing a copy of the provided
	 * ContextAccessRulesManager.
	 *
	 * @param sourceManager the rules manager
	 */
	public ContextAccessRulesManager(Context context, ContextAccessRulesManager sourceManager) {
		this.context = context;
		this.contextSiteTree = sourceManager.contextSiteTree;
		this.rules = new HashMap<>(sourceManager.rules.size());
		Map<SiteTreeNode, AccessRule> userRules;
		for (Map.Entry<Integer, Map<SiteTreeNode, AccessRule>> entry : sourceManager.rules.entrySet()) {
			userRules = new HashMap<>(entry.getValue());
			this.rules.put(entry.getKey(), userRules);
		}
	}

	/**
	 * Get the mapping of rules for the user or initialize if needed.
	 *
	 * @param userId the user id
	 * @return the user rules
	 */
	private Map<SiteTreeNode, AccessRule> getUserRules(int userId) {
		Map<SiteTreeNode, AccessRule> userRules = rules.get(userId);
		if (userRules == null) {
			userRules = new HashMap<>();
			this.rules.put(userId, userRules);
		}
		return userRules;
	}

	/**
	 * Gets the access rule for a user and a node, if any.
	 *
	 * @param userId the user id
	 * @param node the node
	 * @return the rule
	 */
	public AccessRule getDefinedRule(int userId, SiteTreeNode node) {
		AccessRule rule = getUserRules(userId).get(node);
		return rule == null ? AccessRule.INHERIT : rule;
	}

	/**
	 * Adds an access rule for a user and a node.
	 *
	 * @param userId the user id
	 * @param node the node
	 * @param rule the rule
	 * @return the access rule
	 */
	public void addRule(int userId, SiteTreeNode node, AccessRule rule) {
		if (log.isDebugEnabled()) {
			log.debug("Adding rule for user " + userId + " and node " + node + ": " + rule);
		}

		// If the rule is INHERIT (default), remove it from the rules mapping as there's no need to
		// store it there
		if (rule == AccessRule.INHERIT) {
			getUserRules(userId).remove(node);
		} else {
			getUserRules(userId).put(node, rule);
		}
	}

	/**
	 * Infers the rule that corresponds to a site tree node.
	 * <p>
	 * If a rule was explicitly defined for the specified node, it is returned directly. Otherwise,
	 * an inference algorithm is used to detect the matching rules for each node based on its
	 * ancestors in the URL: the rule inferred is the one that has been explicitly defined for the
	 * closest ancestor.
	 * </p>
	 * <p>
	 * The root has a fixed corresponding value of {@link AccessRule#UNKNOWN}, so if no rules are
	 * specified for any of the ancestors of a node, it defaults to {@link AccessRule#UNKNOWN}.
	 * </p>
	 *
	 * @param userId the user id
	 * @param node the node
	 * @return the access rule inferred
	 */
	public AccessRule inferRule(int userId, SiteTreeNode node) {
		Map<SiteTreeNode, AccessRule> userRules = getUserRules(userId);
		// First of all, check if we have an explicit rule for the node
		AccessRule rule;
		rule = userRules.get(node);
		if (rule != null && rule != AccessRule.INHERIT) {
			return rule;
		}

		String hostname;
		List<String> path = null;
		try {
			path = context.getUrlParamParser().getTreePath(node.getUri());
			hostname = UriUtils.getHostName(node.getUri());
		} catch (URIException e) {
			log.error("An error occurred while infering access rules: " + e.getMessage(), e);
			return AccessRule.UNKNOWN;
		}

		// Find the node corresponding to the hostname of the url
		AccessRule inferredRule = AccessRule.UNKNOWN;
		SiteTreeNode parent = contextSiteTree.getRoot().findChild(hostname);
		if (parent != null) {
			rule = userRules.get(parent);
			if (rule != null && rule != AccessRule.INHERIT) {
				inferredRule = rule;
			}
		}

		if (parent == null || path == null || path.isEmpty()) {
			return inferredRule;
		}

		// Replace the last 'segment' of the path with the actual node name
		path.set(path.size() - 1, node.getNodeName());

		String pathSegment;

		// Navigate the tree down trying to find the target node, making sure we store the defined
		// access rule at each step, if different from INHERIT. This allows us to have the right
		// behavior and infer the access rule. We start with UNKNOWN
		for (int i = 0; i < path.size(); i++) {
			pathSegment = path.get(i);
			if (pathSegment != null && !pathSegment.equals("")) {
				// Find the child node that matches the segment
				parent = parent.findChild(pathSegment);
				if (parent == null) {
					log.warn("Unable to find path segment while infering rule for " + node + ": "
							+ pathSegment);
					break;
				}
				// Save it's access rule, if anything relevant
				rule = userRules.get(parent);
				if (rule != null && rule != AccessRule.INHERIT) {
					inferredRule = rule;
				}
			}
		}
		return inferredRule;
	}

	/**
	 * Clear any existing rules and copies the access rules from another rules manager for the
	 * provided list of users (to which the "Unauthenticated user" is added).
	 *
	 * @param sourceManager the source manager
	 * @param users the users for which to copy rules
	 */
	public void copyRulesFrom(ContextAccessRulesManager sourceManager, List<User> users) {
		this.rules.clear();
		Map<SiteTreeNode, AccessRule> userRules;
		// Copy the user rules for the provided users
		for (User user : users) {
			Map<SiteTreeNode, AccessRule> sourceRules = sourceManager.rules.get(user.getId());
			if (sourceRules == null) {
				continue;
			}
			userRules = new HashMap<>(sourceManager.rules.get(user.getId()));
			if (userRules != null) {
				this.rules.put(user.getId(), userRules);
			}
		}
		// Also copy the rules for the unauthenticated user, which will always be there
		Map<SiteTreeNode, AccessRule> sourceRules = sourceManager.rules.get(UNAUTHENTICATED_USER_ID);
		if (sourceRules != null) {
			userRules = new HashMap<>(sourceManager.rules.get(UNAUTHENTICATED_USER_ID));
			if (userRules != null) {
				this.rules.put(UNAUTHENTICATED_USER_ID, userRules);
			}
		}

		this.contextSiteTree = sourceManager.contextSiteTree;
	}

	public ContextSiteTree getContextSiteTree() {
		return contextSiteTree;
	}

	public void reloadContextSiteTree(Session session) {
		this.contextSiteTree.reloadTree(session, context);
	}

	/**
	 * Generates a list of string representations (serialization) of the rules contained in this
	 * rules manager. Each of the entries can later be imported using the
	 * {@link #importSerializedRule(String)} method.
	 *
	 * @return the list of representations
	 */
	protected List<String> exportSerializedRules() {
		List<String> exported = new LinkedList<>();

		StringBuilder serializedRule;
		for (Entry<Integer, Map<SiteTreeNode, AccessRule>> userRulesEntry : rules.entrySet()) {
			for (Entry<SiteTreeNode, AccessRule> ruleEntry : userRulesEntry.getValue().entrySet()) {
				serializedRule = new StringBuilder(50);
				serializedRule.append(userRulesEntry.getKey().toString());
				serializedRule.append(SERIALIZATION_SEPARATOR);
				serializedRule.append(ruleEntry.getValue().name()).append(SERIALIZATION_SEPARATOR);
				// Note: encode the name as it may contain special characters
				serializedRule.append(Base64.encodeBase64String(ruleEntry.getKey().getNodeName().getBytes()));
				serializedRule.append(SERIALIZATION_SEPARATOR);
				// Note: there's no need to escape the URI as it's the last value of the
				// serialization string and as we're using the URL escaped version (which cannot
				// contain the separator)
				serializedRule.append(ruleEntry.getKey().getUri().getEscapedURI());
				exported.add(serializedRule.toString());
			}
		}
		return exported;
	}

	/**
	 * Import a rule from a serialized representation. The rule should have been exported via the
	 * {@link #exportSerializedRules()} method.
	 *
	 * @param serializedRule the serialized rule
	 */
	protected void importSerializedRule(String serializedRule) {
		try {
			String[] values = serializedRule.split(Character.toString(SERIALIZATION_SEPARATOR), 4);
			int userId = Integer.parseInt(values[0]);
			AccessRule rule = AccessRule.valueOf(values[1]);
			String nodeName = new String(Base64.decodeBase64(values[2]));
			URI uri = new URI(values[3], true);
			SiteTreeNode node = new SiteTreeNode(nodeName, uri);
			getUserRules(userId).put(node, rule);
			if (log.isDebugEnabled()) {
				log.debug(String.format(
						"Imported access control rule (context, userId, node, rule): (%d, %d, %s, %s) ",
						context.getIndex(), userId, uri.toString(), rule));
			}
		} catch (Exception ex) {
			log.error("Unable to import serialized rule for context " + context.getIndex() + ":"
					+ serializedRule, ex);
		}
	}

	/**
	 * Generates and returns the map of rules that are associated to SiteTreeNodes which don't exist
	 * in the current {@link ContextSiteTree}.
	 *
	 * @param userId the user id
	 * @return the map of rules which are associated to nodes not in the context tree
	 */
	public Map<SiteTreeNode, AccessRule> computeHangingRules(int userId) {
		Map<SiteTreeNode, AccessRule> rules = new HashMap<>(getUserRules(userId));
		if (rules.isEmpty()) {
			return rules;
		}

		// We make a traversal of the context site tree and remove all nodes from the map
		@SuppressWarnings("unchecked")
		Enumeration<SiteTreeNode> en = contextSiteTree.getRoot().depthFirstEnumeration();
		while (en.hasMoreElements()) {
			// Unfortunately the enumeration isn't genericized so we need to downcast when calling
			// nextElement():
			SiteTreeNode node = en.nextElement();
			rules.remove(node);
		}

		if (log.isDebugEnabled()) {
			log.debug(String.format("Identified hanging rules for context %d and user %d: %s",
					context.getIndex(), userId, rules));
		}
		return rules;

	}
}
