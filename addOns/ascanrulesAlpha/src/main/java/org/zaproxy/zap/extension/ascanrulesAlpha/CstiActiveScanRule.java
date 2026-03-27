package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.ClientSideDetails;

public class CstiActiveScanRule extends AbstractAppPlugin {

    private static final Logger LOGGER = LogManager.getLogger(CstiActiveScanRule.class);
    private static final int PLUGIN_ID = 100001;
    private static final String MESSAGE_PREFIX = "ascanalpha.csti.";

    private final Set<String> scannedUrls = ConcurrentHashMap.newKeySet();

    @Override
    public void init() {
        scannedUrls.clear();
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public void scan() {
        if (isStop()) return;

        HttpMessage msg = getBaseMsg();
        String fullUrl = msg.getRequestHeader().getURI().toString();

        if (!scannedUrls.add(fullUrl)) return;

        ExtensionClientIntegration extClient =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionClientIntegration.class);

        if (extClient == null) {
            LOGGER.debug("Client add-on not available.");
            raiseDebugAlert("Client add-on not available.", fullUrl);
            return;
        }

        ClientNode node = extClient.getClientNode(fullUrl, false, false);
        if (node == null) {
            String bareUrl = stripQueryAndFragment(fullUrl);
            if (!bareUrl.equals(fullUrl)) {
                node = extClient.getClientNode(bareUrl, false, false);
            }
        }

        if (node == null) {
            LOGGER.debug("No client spider node for {} (tried full and bare URL).", fullUrl);
            raiseDebugAlert("No client spider node found for URL.", fullUrl);
            return;
        }

        List<String> findings = new ArrayList<>();
        collectFindings(node, findings);

        if (findings.isEmpty()) {
            LOGGER.debug("Node found for {} but no usable components.", fullUrl);
            raiseDebugAlert("Client node found, but no usable components.", fullUrl);
            return;
        }

        LOGGER.info("CSTI step-1: {} component(s) for {}", findings.size(), fullUrl);
        findings.forEach(f -> LOGGER.info("  {}", f));

        newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setName(getName() + " [step-1 discovery]")
                .setDescription("Client Spider data found for this URL.")
                .setOtherInfo(String.join("\n", findings))
                .raise();
    }

    private void raiseDebugAlert(String reason, String fullUrl) {
        newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setName(getName() + " [debug]")
                .setDescription(reason)
                .setOtherInfo("URL: " + fullUrl)
                .raise();
    }

    private String stripQueryAndFragment(String fullUrl) {
        if (fullUrl == null) {
            return null;
        }

        int queryIndex = fullUrl.indexOf('?');
        int fragmentIndex = fullUrl.indexOf('#');

        int cutIndex;
        if (queryIndex == -1) {
            cutIndex = fragmentIndex;
        } else if (fragmentIndex == -1) {
            cutIndex = queryIndex;
        } else {
            cutIndex = Math.min(queryIndex, fragmentIndex);
        }

        return cutIndex >= 0 ? fullUrl.substring(0, cutIndex) : fullUrl;
    }

    private void collectFindings(ClientNode node, List<String> findings) {
        ClientSideDetails details = node.getUserObject();

        if (details != null) {
            for (ClientSideComponent component : details.getComponents()) {
                String line = describeComponent(component);
                if (line != null) {
                    findings.add(line);
                }
            }
        }

        // the site root node's children contains the actual page nodes with components.
        for (int i = 0; i < node.getChildCount(); i++) {
            collectFindings(node.getChildAt(i), findings);
        }
    }

    private static String describeComponent(ClientSideComponent component) {
        ClientSideComponent.Type type = component.getType();

        if (type == ClientSideComponent.Type.REDIRECT || type == ClientSideComponent.Type.CONTENT_LOADED) {
            return null;
        }

        return String.format(
                "type=%-14s  tag=%-10s  id=%-20s  href=%s",
                type,
                nullToEmpty(component.getTagName()),
                nullToEmpty(component.getId()),
                nullToEmpty(component.getHref()));
    }
    private static String nullToEmpty(String value) {
        return value != null ? value : "-";
    }
}