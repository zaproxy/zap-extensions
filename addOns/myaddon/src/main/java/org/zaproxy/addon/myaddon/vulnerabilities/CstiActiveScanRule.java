package org.zaproxy.addon.myaddon.vulnerabilities;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpMessage;

public class CstiActiveScanRule extends AbstractAppParamPlugin {

    private static final Logger LOGGER = LogManager.getLogger(CstiActiveScanRule.class);

    // Replace with a properly reserved / unused ID before upstreaming.
    private static final int PLUGIN_ID = 100001;

    private static final String MESSAGE_PREFIX = "myaddon.csti.";
    private final Random random = new Random();

    @Override
    public int getId() {
        return PLUGIN_ID;
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
    public int getCategory() {
        return Category.INJECTION;
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
    public void scan(HttpMessage msg, NameValuePair originalParam) {
        if (isStop()) {
            return;
        }

        LOGGER.info(
                "CSTI rule invoked: param={} url={}",
                originalParam.getName(),
                msg.getRequestHeader().getURI());

        String baselineBody = getBaseMsg().getResponseBody().toString();

        int a = 10 + random.nextInt(20);
        int b = 10 + random.nextInt(20);
        String expected = Integer.toString(a * b);

        Map<String, String> payloads = new LinkedHashMap<>();
        payloads.put("{{" + a + "*" + b + "}}", expected);
        payloads.put("${" + a + "*" + b + "}", expected);
        payloads.put("[[" + a + "*" + b + "]]", expected);



        for (Map.Entry<String, String> entry : payloads.entrySet()) {
            if (isStop()) {
                return;
            }

            String payload = entry.getKey();
            HttpMessage testMsg = getNewMsg();
            setParameter(testMsg, originalParam.getName(), payload);

            try {
                sendAndReceive(testMsg);
                decodeResponseBody(testMsg);

                String responseBody = testMsg.getResponseBody().toString();

                boolean expectedWasAlreadyPresent = baselineBody.contains(expected);
                boolean payloadStillPresent = responseBody.contains(payload);
                boolean expectedPresent = responseBody.contains(expected);

                if (!expectedWasAlreadyPresent && expectedPresent && !payloadStillPresent) {
                    newAlert()
                            .setRisk(Alert.RISK_MEDIUM)
                            .setConfidence(Alert.CONFIDENCE_LOW)
                            .setAttack(payload)
                            .setEvidence(expected)
                            .setOtherInfo("Heuristic CSTI detection; verify in browser/DOM.")
                            .setMessage(testMsg)
                            .raise();
                    return;
                }
            } catch (IOException e) {
                LOGGER.debug("Error scanning parameter {}", originalParam.getName(), e);
            }
        }
    }
}