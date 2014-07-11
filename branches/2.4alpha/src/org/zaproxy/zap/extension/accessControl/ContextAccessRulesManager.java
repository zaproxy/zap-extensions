/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
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

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.accessControl.widgets.ContextSiteTree;
import org.zaproxy.zap.extension.accessControl.widgets.SiteTreeNode;
import org.zaproxy.zap.extension.accessControl.widgets.UriUtils;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;

/**
 * 
 * 
 * 
 * 
 * 
 * Note: In order to store access rules for unauthenticated visitors, we'll use -1 as the id, which
 * is an id that should not be generated for normal users.
 */
public class ContextAccessRulesManager {
	private Context context;
	private Map<Integer, Map<SiteTreeNode, AccessRule>> rules;
	private static final Logger log = Logger.getLogger(ContextAccessRulesManager.class);
	private ContextSiteTree contextSiteTree;
	private static final char SERIALIZATION_SEPARATOR = '`';
	/**
	 * In order to store access rules for unauthenticated visitors, we'll use -1 as the id, which is
	 * an id that should not be generated for normal users.
	 */
	public static final int UNAUTHENTICATED_USER_ID = -1;

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
		// If the rule is INHERIT (default), remove it from the rules mapping as there's no need to
		// store it there
		if (rule == AccessRule.INHERIT)
			getUserRules(userId).remove(node);
		else
			getUserRules(userId).put(node, rule);
	}

	public AccessRule inferRule(int userId, SiteTreeNode node) {
		Map<SiteTreeNode, AccessRule> userRules = getUserRules(userId);
		List<String> path = null;
		try {
			path = context.getUrlParamParser().getTreePath(node.getUri());
		} catch (URIException e) {
			e.printStackTrace();

		}

		// Check the hostname
		String hostname;
		try {
			hostname = UriUtils.getHostName(node.getUri());
		} catch (URIException e) {
			e.printStackTrace();
			return AccessRule.UNKNOWN;
		}

		AccessRule rule, inferredRule = AccessRule.UNKNOWN;
		SiteTreeNode parent = contextSiteTree.getRoot().findChild(hostname);
		if (parent != null) {
			rule = userRules.get(parent);
			if (rule != null && rule != AccessRule.INHERIT)
				inferredRule = rule;
		}

		if (parent == null || path == null || path.isEmpty())
			return inferredRule;

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
					log.info("Unable to find path segment while infering rule: " + pathSegment);
					break;
				}
				// Save it's access rule, if anything relevant
				rule = userRules.get(parent);
				if (rule != null && rule != AccessRule.INHERIT)
					inferredRule = rule;
			}
		}
		return inferredRule;
	}

	/**
	 * Clear any existing rules and copies the access rules from another rules manager for the
	 * provided list of users.
	 *
	 * @param sourceManager the source manager
	 * @param users the users for which to copy rules
	 */
	public void copyRulesFrom(ContextAccessRulesManager sourceManager, List<User> users) {
		this.rules.clear();
		Map<SiteTreeNode, AccessRule> userRules;
		for (User user : users) {
			Map<SiteTreeNode, AccessRule> sourceRules = sourceManager.rules.get(user.getId());
			if (sourceRules == null)
				continue;
			userRules = new HashMap<>(sourceManager.rules.get(user.getId()));
			if (userRules != null)
				this.rules.put(user.getId(), userRules);
		}
		this.contextSiteTree = sourceManager.contextSiteTree;
	}

	public ContextSiteTree getContextSiteTree() {
		return contextSiteTree;
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
				serializedRule.append(ruleEntry.getValue().toString()).append(SERIALIZATION_SEPARATOR);
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
			if (log.isDebugEnabled())
				log.debug(String.format(
						"Imported access control rule (context, userId, node, rule): (%d, %d, %s, %s) ",
						context.getIndex(), userId, uri.toString(), rule));
		} catch (Exception ex) {
			log.error("Unable to import serialized rule for context " + context.getIndex() + ":"
					+ serializedRule, ex);
		}
	}
}
