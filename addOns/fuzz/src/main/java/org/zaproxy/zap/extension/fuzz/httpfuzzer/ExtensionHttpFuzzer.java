/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.httpfuzzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import javax.swing.ImageIcon;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.extension.anticsrf.ExtensionAntiCSRF;
import org.zaproxy.zap.extension.fuzz.ExtensionFuzz;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.messagelocations.TextHttpMessageLocationReplacerFactory;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.AntiCsrfHttpFuzzerMessageProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.FuzzerHttpMessageScriptProcessorAdapterUIHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.HttpFuzzerProcessorScript;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.HttpFuzzerReflectionDetectorStateHighlighter;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.HttpFuzzerReflectionDetectorUIHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.RequestContentLengthUpdaterProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.UserHttpFuzzerMessageProcessorUIHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.tagcreator.HttpFuzzerMessageProcessorTagStateHighlighter;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.tagcreator.HttpFuzzerMessageProcessorTagUIHandler;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.ui.HttpFuzzAttackPopupMenuItem;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.ui.HttpFuzzerResultStateHighlighter;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacers;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.extension.search.ExtensionSearch;
import org.zaproxy.zap.extension.search.HttpSearcher;
import org.zaproxy.zap.extension.search.SearchResult;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;

public class ExtensionHttpFuzzer extends ExtensionAdaptor {

    private static final ImageIcon HTTP_FUZZER_PROCESSOR_SCRIPT_ICON =
            new ImageIcon(ZAP.class.getResource("/resource/icon/16/script-fuzz.png"));

    private static final List<Class<? extends Extension>> DEPENDENCIES;

    static {
        List<Class<? extends Extension>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionFuzz.class);
        DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    private HttpFuzzerHandler httpFuzzerHandler;

    private HttpFuzzerSearcher httpFuzzerSearcher;

    private ScriptType scriptType;

    public ExtensionHttpFuzzer() {
        super();
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("fuzz.httpfuzzer.description");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void init() {
        httpFuzzerHandler = new HttpFuzzerHandler();

        MessageLocationReplacers.getInstance()
                .addReplacer(HttpMessage.class, new TextHttpMessageLocationReplacerFactory());
    }

    @Override
    public void initView(ViewDelegate view) {
        super.initView(view);

        ExtensionScript extensionScript =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
        if (extensionScript != null) {
            scriptType =
                    new ScriptType(
                            HttpFuzzerProcessorScript.TYPE_NAME,
                            "fuzz.httpfuzzer.script.type.fuzzerprocessor",
                            HTTP_FUZZER_PROCESSOR_SCRIPT_ICON,
                            true,
                            true);
            extensionScript.registerScriptType(scriptType);

            httpFuzzerHandler.addFuzzerMessageProcessorUIHandler(
                    new FuzzerHttpMessageScriptProcessorAdapterUIHandler(extensionScript));
        }
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        ExtensionFuzz extensionFuzz =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionFuzz.class);
        extensionFuzz.addFuzzerHandler(httpFuzzerHandler);

        if (getView() != null) {
            extensionHook
                    .getHookMenu()
                    .addPopupMenuItem(
                            new HttpFuzzAttackPopupMenuItem(extensionFuzz, httpFuzzerHandler));

            ExtensionSearch extensionSearch =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionSearch.class);
            if (extensionSearch != null) {
                httpFuzzerSearcher = new HttpFuzzerSearcher(extensionFuzz);
                extensionSearch.addCustomHttpSearcher(httpFuzzerSearcher);
            }

            httpFuzzerHandler.addFuzzerMessageProcessorUIHandler(
                    new RequestContentLengthUpdaterProcessorUIHandler());
            httpFuzzerHandler.addFuzzerMessageProcessorUIHandler(
                    new HttpFuzzerReflectionDetectorUIHandler());

            addFuzzResultStateHighlighter(new HttpFuzzerReflectionDetectorStateHighlighter());

            ExtensionUserManagement extensionUserManagement =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionUserManagement.class);
            if (extensionUserManagement != null) {
                httpFuzzerHandler.addFuzzerMessageProcessorUIHandler(
                        new UserHttpFuzzerMessageProcessorUIHandler(extensionUserManagement));
            }

            ExtensionAntiCSRF extensionAntiCSRF =
                    Control.getSingleton()
                            .getExtensionLoader()
                            .getExtension(ExtensionAntiCSRF.class);
            if (extensionAntiCSRF != null) {
                httpFuzzerHandler.addFuzzerMessageProcessorUIHandler(
                        new AntiCsrfHttpFuzzerMessageProcessorUIHandler(extensionAntiCSRF));
            }

            httpFuzzerHandler.addFuzzerMessageProcessorUIHandler(
                    new HttpFuzzerMessageProcessorTagUIHandler());
            addFuzzResultStateHighlighter(new HttpFuzzerMessageProcessorTagStateHighlighter());
        }
    }

    @Override
    public void unload() {
        super.unload();

        if (httpFuzzerSearcher != null) {
            ExtensionSearch extensionSearch =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionSearch.class);
            extensionSearch.removeCustomHttpSearcher(httpFuzzerSearcher);
        }

        if (getView() != null) {
            ExtensionScript extensionScript =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
            if (extensionScript != null) {
                extensionScript.removeScriptType(scriptType);
            }
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    public void addFuzzResultStateHighlighter(HttpFuzzerResultStateHighlighter highlighter) {
        httpFuzzerHandler
                .getHttpFuzzResultsContentPanel()
                .addFuzzResultStateHighlighter(highlighter);
    }

    public void removeFuzzResultStateHighlighter(HttpFuzzerResultStateHighlighter highlighter) {
        httpFuzzerHandler
                .getHttpFuzzResultsContentPanel()
                .removeFuzzResultStateHighlighter(highlighter);
    }

    public <T1 extends HttpFuzzerMessageProcessor, T2 extends HttpFuzzerMessageProcessorUI<T1>>
            void addFuzzerMessageProcessorUIHandler(
                    HttpFuzzerMessageProcessorUIHandler<T1, T2> handler) {
        httpFuzzerHandler.addFuzzerMessageProcessorUIHandler(handler);
    }

    public <T1 extends HttpFuzzerMessageProcessor, T2 extends HttpFuzzerMessageProcessorUI<T1>>
            void removeFuzzerMessageProcessorUIHandler(
                    HttpFuzzerMessageProcessorUIHandler<T1, T2> handler) {
        httpFuzzerHandler.removeFuzzerMessageProcessorUIHandler(handler);
    }

    public static class HttpFuzzerSearcher implements HttpSearcher {

        public static final String SEARCHER_NAME =
                Constant.messages.getString("fuzz.httpfuzzer.searcher.name");

        private final ExtensionFuzz extensionFuzz;

        public HttpFuzzerSearcher(ExtensionFuzz extensionFuzz) {
            this.extensionFuzz = extensionFuzz;
        }

        @Override
        public String getName() {
            return SEARCHER_NAME;
        }

        @Override
        public List<SearchResult> search(Pattern pattern, boolean inverse) {
            List<SearchResult> results = new ArrayList<>();
            List<HttpFuzzer> fuzzers = extensionFuzz.getFuzzers(HttpFuzzer.class);
            for (HttpFuzzer fuzzer : fuzzers) {
                results.addAll(fuzzer.search(pattern, inverse));
            }
            return results;
        }

        @Override
        public List<SearchResult> search(Pattern pattern, boolean inverse, int maximumMatches) {
            List<SearchResult> results = new ArrayList<>();
            int matchesLeftForMax = maximumMatches;
            List<HttpFuzzer> fuzzers = extensionFuzz.getFuzzers(HttpFuzzer.class);
            for (HttpFuzzer fuzzer : fuzzers) {
                if (matchesLeftForMax <= 0) {
                    break;
                }
                List<SearchResult> fuzzerResult =
                        fuzzer.search(pattern, inverse, matchesLeftForMax);
                matchesLeftForMax -= fuzzerResult.size();
                results.addAll(fuzzerResult);
            }
            return results;
        }
    }
}
