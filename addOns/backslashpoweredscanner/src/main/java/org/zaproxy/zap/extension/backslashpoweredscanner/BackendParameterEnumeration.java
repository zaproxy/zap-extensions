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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Active Plugin for Backend Parameter Injection by using Backslash Powered Scanning, a novel
 * approach capable of finding and confirming both known and unknown classes of server-side
 * injection vulnerabilities.
 *
 * @author mqliang
 */
public class BackendParameterEnumeration extends BackSlashPoweredAbstractAppParamPlugin {
    private static final String SCANNER_MESSAGE_PREFIX =
            "backslashpoweredscanner.backendparameterenumeration.";
    private static final String paramFile = "txt/params";
    private static final Logger log = Logger.getLogger(BackendParameterEnumeration.class);

    // a list of often used backend parameters
    public static HashSet<String> paramNames = new HashSet<>();

    @Override
    public int getId() {
        return 40030;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(SCANNER_MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(SCANNER_MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER; // allows information (parameters) to be gathered
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(SCANNER_MESSAGE_PREFIX + "soln");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(SCANNER_MESSAGE_PREFIX + "refs");
    }

    @Override
    public void init() {
        BackendParameterEnumeration.paramNames = loadFile(paramFile);
    }

    @Override
    public void scan(HttpMessage msg, String parameter, String baseValue) {
        PayloadInjector injector = new PayloadInjector(parameter, baseValue, log);

        Attack base =
                injector.buildAttack(
                        parameter,
                        baseValue
                                + "&"
                                + Utilities.randomString(6)
                                + "=%3c%61%60%27%22%24%7b%7b%5c",
                        false);
        for (int i = 0; i < 4; i++) {
            base.updateWith(
                    injector.buildAttack(
                            parameter,
                            baseValue
                                    + "&"
                                    + Utilities.randomString((i + 1) * (i + 1))
                                    + "=%3c%61%60%27%22%24%7b%7b%5c",
                            false));
        }

        ArrayList<Attack> attacks = new ArrayList<>();
        for (String candidate : paramNames) {
            Attack paramGuess =
                    injector.buildAttack(
                            parameter,
                            baseValue + "&" + candidate + "=%3c%61%60%27%22%24%7b%7b%5c",
                            false);
            if (!Utilities.similar(base, paramGuess)) {
                Attack confirmParamGuess =
                        injector.buildAttack(
                                parameter,
                                baseValue + "&" + candidate + "=%3c%61%60%27%22%24%7b%7b%5c",
                                false);
                base.updateWith(
                        injector.buildAttack(
                                parameter,
                                baseValue + "&" + candidate + "z=%3c%61%60%27%22%24%7b%7b%5c",
                                false));
                if (!Utilities.similar(base, confirmParamGuess)) {
                    Probe validParam =
                            new Probe(
                                    "Backend param: " + candidate,
                                    "&" + candidate + "=%3c%61%60%27%22%24%7b%7b%5c",
                                    "&" + candidate + "=%3c%62%60%27%22%24%7b%7b%5c");
                    validParam.setEscapeStrings(
                            "&"
                                    + Utilities.randomString(candidate.length())
                                    + "=%3c%61%60%27%22%24%7b%7b%5c",
                            "&" + candidate + "z=%3c%61%60%27%22%24%7b%7b%5c");
                    validParam.setRandomAnchor(false);

                    ArrayList<Attack> confirmed = injector.fuzz(base, validParam);
                    if (!confirmed.isEmpty()) {
                        log.info("Identified backend parameter: " + candidate);
                        attacks.addAll(confirmed);
                    }
                }
            } else {
                base.updateWith(paramGuess);
            }
        }

        raiseAlert(attacks, parameter);
    }

    private void raiseAlert(ArrayList<Attack> attacks, String parameter) {
        for (Attack attack : attacks) {
            this.bingo(
                    Alert.RISK_HIGH,
                    Alert.CONFIDENCE_MEDIUM,
                    Constant.messages.getString(SCANNER_MESSAGE_PREFIX + "name"),
                    getDescription(),
                    null,
                    parameter,
                    attack.getPayload(),
                    null,
                    getSolution(),
                    attack.getMessage());
        }
    }

    private HashSet<String> loadFile(String file) {
        HashSet<String> strings = new HashSet<>();
        BufferedReader reader = null;
        File f = new File(Constant.getZapHome() + File.separator + file);
        if (!f.exists()) {
            log.error("No such file: " + f.getAbsolutePath());
            return strings;
        }
        try {
            String line;
            reader = new BufferedReader(new FileReader(f));
            while ((line = reader.readLine()) != null) {
                strings.add(line.trim());
            }
        } catch (IOException e) {
            log.error("Error on opening/reading parameter file. Error: " + e.getMessage(), e);
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    log.debug("Error on closing the file reader. Error: " + e.getMessage(), e);
                }
            }
        }
        return strings;
    }
}
