/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.paramdigger;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpSender;

public class HeaderGuesser implements Runnable {

    private int id;
    private GuesserScan scan;
    private HttpSender httpSender;
    private ExecutorService executor;
    private ParamDiggerConfig config;

    private static final String DEFAULTWORDLISTPATH =
            Constant.getZapHome() + "/wordlists/header_list.txt";
    private Path defaultWordListFile;
    private List<String> defaultWordList;

    private Path customWordListFile;
    private List<String> customWordList;
    private List<String> wordlist;

    public HeaderGuesser(
            int id, GuesserScan scan, HttpSender httpSender, ExecutorService executor) {
        this.id = id;
        this.scan = scan;
        this.httpSender = httpSender;
        this.executor = executor;
        this.config = scan.getConfig();

        if (config.getUsePredefinedHeaderWordlists()) {
            defaultWordListFile = Paths.get(DEFAULTWORDLISTPATH);
            defaultWordList = Utils.read(defaultWordListFile);
        }
        if (config.getUseCustomHeaderWordlists()) {
            customWordListFile = Paths.get(config.getCustomUrlWordlistPath());
            customWordList = Utils.read(customWordListFile);
        }

        if (defaultWordList != null && customWordList != null) {
            Set<String> set = new HashSet<>();
            set.addAll(defaultWordList);
            set.addAll(customWordList);
            wordlist = new ArrayList<>();

            for (String param : set) {
                wordlist.add(param);
            }
        } else if (customWordList == null && defaultWordList != null) {
            wordlist = defaultWordList;
        } else {
            wordlist = customWordList;
        }
        this.scan.setMaximum(1);
    }

    @Override
    public void run() {
        // TODO add forwarding header and bruteforce header guess tasks
    }

    public void startGuess(Method method, List<String> wordlist) {}
}
