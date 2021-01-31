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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.io.IOException;
import org.apache.log4j.Logger;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpHeader;
/**
 * The CORS active scan rule identifies Cross-Origin Resource Sharing (CORS) support 
 * and overly lenient or buggy implementations
 *
 * @author CravateRouge
 */
public class CORSActiveScanRule extends AbstractAppPlugin {
    private static Logger LOG = Logger.getLogger(CORSActiveScanRule.class);
    private static final String RANDOM_NAME= RandomStringUtils.random(8, true, true);

    @Override
    public void scan() {
        HttpMessage baseMsg = getBaseMsg();
        URI uri = baseMsg.getRequestHeader().getURI();
        String authority = uri.getEscapedAuthority();
        String scheme = uri.getScheme();
        String handyScheme = scheme + "://";

        // Order of likelihood and severity
        String[] payloads = {
            handyScheme+RANDOM_NAME+".com",
            "null",
            handyScheme+RANDOM_NAME+"."+authority,
            handyScheme+authority+"."+RANDOM_NAME+".com",
            // URL encoded backtick used to bypass weak Regex matching only alphanumeric chars to validate the domain: https://www.corben.io/tricky-CORS/
            handyScheme+authority+"%60"+RANDOM_NAME+".com",
            null,
            handyScheme+authority
        };

        boolean secScheme = false;
        if(scheme == "https"){
            secScheme = true;
            payloads[5] = "http://"+authority; 
        }

        for (String payload : payloads) {
            HttpMessage msg = getNewMsg();
            msg.getRequestHeader().setHeader("Origin",payload);
            try {
                sendAndReceive(msg);
                String acaoKey = HttpHeader.ACCESS_CONTROL_ALLOW_ORIGIN;
                String acao = msg.getResponseHeader().getHeader(acaoKey);
                // If there is an ACAO header an alert will be triggered
                if(acao == null)
                    continue;

                String name = getName();
                int risk = Alert.RISK_INFO;
                String evidence = acaoKey+": "+acao;
                int wasc = 14;
                int cwe = 942;
                String desc = getDescription();
                boolean vuln = false;

                // Evaluates the risk for this alert
                if(acao.contains("*")){
                    vuln = true;
                    risk = Alert.RISK_MEDIUM;
                }
                else if (acao.contains(RANDOM_NAME) || acao.contains("null") 
                || (secScheme && acao.contains("http:"))){
                    vuln = true;
                    // If authenticated AJAX requests are allowed, the risk is higher
                    String acacKey = "Access-Control-Allow-Credentials";
                    String acac = msg.getResponseHeader().getHeader(acacKey);
                    if(acac == null)
                        risk = Alert.RISK_MEDIUM;
                    else{
                        risk = Alert.RISK_HIGH;
                        evidence += "\n"+acacKey+": "+acac;
                    }                       
                }
                if(vuln){
                    name = getConstantStr("vuln.name");
                    desc = getConstantStr("vuln.desc");
                }

                newAlert()
                .setName(name)
                .setMessage(msg)
                .setRisk(risk)
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setParam("Header")
                .setAttack("Origin: "+payload)
                .setEvidence(evidence)
                .setWascId(wasc)
                .setCweId(cwe)
                .setDescription(desc)
                .raise();
                return;
            } catch (IOException e) {
                LOG.error(e.getMessage(), e);
            }
        }
    }

    @Override
    public int getId() {
        return 40039;
    }

    public String getConstantStr(String suffix){
        return Constant.messages.getString("ascanalpha.cors." + suffix);
    }

    @Override
    public String getName() {
        return getConstantStr("info.name");
    }


    @Override
    public String getDescription() {
        return getConstantStr("info.desc");
    }

    @Override
    public int getCategory() {
        return Category.SERVER;
    }

    @Override
    public String getSolution() {
        return getConstantStr("soln");
    }

    @Override
    public String getReference() {
        return getConstantStr("refs");
    }
}
