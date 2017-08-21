/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.backslashpoweredscanner;

import java.util.ArrayList;
import java.util.TreeSet;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpMessage;

/*
 * BackSlashPoweredAbstractAppParamPlugin extends the AbstractAppParamPlugin interface by providing
 * a useful PayloadInjector class which can fuzz requests
 */
public abstract class BackSlashPoweredAbstractAppParamPlugin extends AbstractAppParamPlugin {
    class PayloadInjector {
        private String parameter;
        private String baseValue;
        private Logger log;

        PayloadInjector(String parameter, String baseValue, Logger log) {
            this.parameter = parameter;
            this.baseValue = baseValue;
            this.log = log;
        }

        ArrayList<Attack> fuzz(Attack baselineAttack, Probe probe) {
            ArrayList<Attack> attacks = new ArrayList<>(2);
            Attack breakAttack = buildAttackFromProbe(probe, probe.getNextBreak());

            if (Utilities.identical(baselineAttack, breakAttack)) {
                return new ArrayList<>();
            }

            for (int k = 0; k < probe.getNextEscapeSet().length; k++) {
                Attack doNotBreakAttack = buildAttackFromProbe(probe, probe.getNextEscapeSet()[k]);
                doNotBreakAttack.updateWith(baselineAttack);
                if (!Utilities.identical(doNotBreakAttack, breakAttack)) {
                    attacks = verify(doNotBreakAttack, breakAttack, probe, k);
                    if (!attacks.isEmpty()) {
                        break;
                    }
                }
            }

            return attacks;
        }

        private Attack buildAttackFromProbe(Probe probe, String payload) {
            boolean randomAnchor = probe.getRandomAnchor();
            byte prefix = probe.getPrefix();

            String anchor = "";
            if (randomAnchor) {
                anchor = Utilities.generateCanary();
            }
            // else {
            //    payload = payload.replace("z", Utilities.generateCanary());
            // }

            String base_payload = payload;
            if (prefix == Probe.PREPEND) {
                payload += baseValue;
            } else if (prefix == Probe.APPEND) {
                payload = baseValue + anchor + payload;
            } else if (prefix == Probe.REPLACE) {
                // payload = payload;
            } else {
                log.error("Unknown payload position");
            }

            HttpMessage req = buildRequest(parameter, payload, probe.useCacheBuster());

            return new Attack(req, probe, base_payload, anchor);
        }

        Attack buildAttack(String parameter, String payload, boolean random) {
            String canary = "";
            if (random) {
                canary = Utilities.generateCanary();
            }

            HttpMessage request = buildRequest(parameter, canary + payload, !random);
            try {
                sendAndReceive(request);
            } catch (Exception e) {
                log.error(
                        "An error occurred enumerating a backend parameter using Backslash Powered Scanner",
                        e);
            }
            return new Attack(request, null, null, canary);
        }

        HttpMessage buildRequest(String paramName, String paramValue, boolean needCacheBuster) {
            HttpMessage request = getNewMsg();
            // add a custom parameter in url if a cache buster is needed
            if (needCacheBuster) {
                TreeSet<HtmlParameter> urlParms = request.getUrlParams();
                urlParms.add(
                        new HtmlParameter(HtmlParameter.Type.url, Utilities.generateCanary(), "1"));
                request.setGetParams(urlParms);
            }
            setParameter(request, paramName, paramValue);
            return request;
        }

        private ArrayList<Attack> verify(
                Attack doNotBreakAttackSeed,
                Attack breakAttackSeed,
                Probe probe,
                int chosen_escape) {
            ArrayList<Attack> attacks = new ArrayList<>(2);
            Attack mergedBreakAttack = new Attack();
            mergedBreakAttack.updateWith(breakAttackSeed);
            Attack mergedDoNotBreakAttack = new Attack();
            mergedDoNotBreakAttack.updateWith(doNotBreakAttackSeed);

            Attack tempDoNotBreakAttack = doNotBreakAttackSeed;

            for (int i = 0; i < Utilities.CONFIRMATIONS; i++) {
                Attack tempBreakAttack = buildAttackFromProbe(probe, probe.getNextBreak());
                mergedBreakAttack.updateWith(tempBreakAttack);

                if (Utilities.similarIsh(
                                mergedDoNotBreakAttack,
                                mergedBreakAttack,
                                tempDoNotBreakAttack,
                                tempBreakAttack)
                        || (probe.getRequireConsistentEvidence()
                                && Utilities.similar(mergedDoNotBreakAttack, tempBreakAttack))) {
                    return new ArrayList<>();
                }

                tempDoNotBreakAttack =
                        buildAttackFromProbe(probe, probe.getNextEscapeSet()[chosen_escape]);
                mergedDoNotBreakAttack.updateWith(tempDoNotBreakAttack);

                if (Utilities.similarIsh(
                                mergedDoNotBreakAttack,
                                mergedBreakAttack,
                                tempDoNotBreakAttack,
                                tempBreakAttack)
                        || (probe.getRequireConsistentEvidence()
                                && Utilities.similar(mergedBreakAttack, tempDoNotBreakAttack))) {
                    return new ArrayList<>();
                }
            }

            // this final probe pair is sent out of order, to prevent alternation false positives
            tempDoNotBreakAttack =
                    buildAttackFromProbe(probe, probe.getNextEscapeSet()[chosen_escape]);
            mergedDoNotBreakAttack.updateWith(tempDoNotBreakAttack);
            Attack tempBreakAttack = buildAttackFromProbe(probe, probe.getNextBreak());
            mergedBreakAttack.updateWith(tempBreakAttack);

            // point is to exploit response attributes that vary in "don't break" responses (but are
            // static in 'break' responses)
            if (Utilities.similarIsh(
                            mergedDoNotBreakAttack,
                            mergedBreakAttack,
                            tempDoNotBreakAttack,
                            tempBreakAttack)
                    || (probe.getRequireConsistentEvidence()
                            && Utilities.similar(mergedBreakAttack, tempDoNotBreakAttack))) {
                return new ArrayList<>();
            }

            attacks.add(mergedBreakAttack);
            attacks.add(mergedDoNotBreakAttack);

            return attacks;
        }
    }
}
