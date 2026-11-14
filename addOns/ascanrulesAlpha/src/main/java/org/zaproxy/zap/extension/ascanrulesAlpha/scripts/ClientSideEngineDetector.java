/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesAlpha.scripts;

import static org.zaproxy.zap.extension.ascanrulesAlpha.CstiActiveScanRule.waitForPageToSettle;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebDriver;

public class ClientSideEngineDetector {

    private static final Logger LOGGER = LogManager.getLogger(ClientSideEngineDetector.class);
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int PROBE_OPERAND = 11111;
    private static final String PROBE_EXPECTED_RESULT =
            Integer.toString(PROBE_OPERAND * PROBE_OPERAND);

    static final Map<String, String> TEMPLATES = new LinkedHashMap<>();

    static {
        TEMPLATES.put("angular", "angular.version");
        TEMPLATES.put("vue", "Vue");
        TEMPLATES.put("mavo", "Mavo");
        TEMPLATES.put("handlebars", "Handlebars");
        TEMPLATES.put("regular", "Regular");
        TEMPLATES.put("template7", "Template7");
        TEMPLATES.put("ejs", "ejs");
        TEMPLATES.put("marko", "Marko");
        TEMPLATES.put("tmpl", "$.tmpl");
        TEMPLATES.put("ember", "Ember");
        TEMPLATES.put("jsrender", "jsrender");
        TEMPLATES.put("dot", "doT");
        TEMPLATES.put("art-template", "template");
        TEMPLATES.put("tempo", "Tempo");
        TEMPLATES.put("transparency", "Transparency");
        TEMPLATES.put("svelte", "__svelte");
        TEMPLATES.put("underscore", "_.template");
        TEMPLATES.put("lit", "litHtmlVersions");
        TEMPLATES.put("mustache", "Mustache");
        TEMPLATES.put("hogan", "Hogan");
        TEMPLATES.put("twig", "Twig");
        TEMPLATES.put("markup", "Markup");
        TEMPLATES.put("dust", "dust");
        TEMPLATES.put("nunjucks", "nunjucks");
        TEMPLATES.put("pug", "pug");
        TEMPLATES.put("loadTemplate", "loadTemplate");
        TEMPLATES.put("pure", "$p");
        TEMPLATES.put("squirrelly", "Sqrl");
        TEMPLATES.put("swig", "swig");
        TEMPLATES.put("icanhaz", "ich");
        TEMPLATES.put("micro-template", "template");
        TEMPLATES.put("juicer", "Juicer");
        TEMPLATES.put("alpine", "Alpine");
    }

    public enum SearchTarget {
        SCRIPT,
        HTML
    }

    public record FunctionSignature(String signature, SearchTarget target) {}

    static final Map<String, List<FunctionSignature>> RENDER_FUNCTIONS = new LinkedHashMap<>();

    static {
        RENDER_FUNCTIONS.put(
                "angular",
                List.of(
                        new FunctionSignature("$compile(", SearchTarget.SCRIPT),
                        new FunctionSignature(".controller(", SearchTarget.SCRIPT),
                        new FunctionSignature(".directive(", SearchTarget.SCRIPT)));
        RENDER_FUNCTIONS.put(
                "vue",
                List.of(
                        new FunctionSignature("new Vue(", SearchTarget.SCRIPT),
                        new FunctionSignature("createApp(", SearchTarget.SCRIPT),
                        new FunctionSignature("Vue.component(", SearchTarget.SCRIPT)));
        RENDER_FUNCTIONS.put(
                "mavo",
                List.of(
                        new FunctionSignature("new Mavo(", SearchTarget.SCRIPT),
                        new FunctionSignature("Mavo.render(", SearchTarget.SCRIPT)
                        // "mv-app" removed – now detected by H3b TEMPLATE_ATTR_PATTERNS
                        ));
        RENDER_FUNCTIONS.put(
                "handlebars",
                List.of(
                        new FunctionSignature("Handlebars.compile(", SearchTarget.SCRIPT),
                        new FunctionSignature("Handlebars.template(", SearchTarget.SCRIPT),
                        new FunctionSignature("Handlebars.registerHelper(", SearchTarget.SCRIPT)));
        RENDER_FUNCTIONS.put(
                "mustache",
                List.of(
                        new FunctionSignature("Mustache.render(", SearchTarget.SCRIPT),
                        new FunctionSignature("Mustache.to_html(", SearchTarget.SCRIPT)));
        RENDER_FUNCTIONS.put(
                "hogan", List.of(new FunctionSignature("Hogan.compile(", SearchTarget.SCRIPT)));
        RENDER_FUNCTIONS.put(
                "twig", List.of(new FunctionSignature("Twig.twig(", SearchTarget.SCRIPT)));
        RENDER_FUNCTIONS.put(
                "dot", List.of(new FunctionSignature("doT.template(", SearchTarget.SCRIPT)));
        RENDER_FUNCTIONS.put(
                "ejs",
                List.of(
                        new FunctionSignature("ejs.render(", SearchTarget.SCRIPT),
                        new FunctionSignature("ejs.compile(", SearchTarget.SCRIPT)));
        RENDER_FUNCTIONS.put(
                "nunjucks",
                List.of(
                        new FunctionSignature("nunjucks.renderString(", SearchTarget.SCRIPT),
                        new FunctionSignature("nunjucks.render(", SearchTarget.SCRIPT),
                        new FunctionSignature("nunjucks.compile(", SearchTarget.SCRIPT)));
        RENDER_FUNCTIONS.put(
                "ember",
                List.of(new FunctionSignature("Ember.Application.create(", SearchTarget.SCRIPT)));
        RENDER_FUNCTIONS.put(
                "pug",
                List.of(
                        new FunctionSignature("pug.compile(", SearchTarget.SCRIPT),
                        new FunctionSignature("pug.render(", SearchTarget.SCRIPT)));
        RENDER_FUNCTIONS.put(
                "dust",
                List.of(
                        new FunctionSignature("dust.render(", SearchTarget.SCRIPT),
                        new FunctionSignature("dust.compile(", SearchTarget.SCRIPT)));
        RENDER_FUNCTIONS.put(
                "underscore", List.of(new FunctionSignature("_.template(", SearchTarget.SCRIPT)));
        RENDER_FUNCTIONS.put(
                "squirrelly",
                List.of(
                        new FunctionSignature("Sqrl.render(", SearchTarget.SCRIPT),
                        new FunctionSignature("Sqrl.compile(", SearchTarget.SCRIPT)));
        RENDER_FUNCTIONS.put(
                "alpine",
                List.of(
                        new FunctionSignature("Alpine.start(", SearchTarget.SCRIPT)
                        // "x-data" removed – now detected by H3b TEMPLATE_ATTR_PATTERNS
                        ));
        RENDER_FUNCTIONS.put(
                "lit",
                List.of(
                        new FunctionSignature("html`", SearchTarget.SCRIPT),
                        new FunctionSignature("LitElement", SearchTarget.SCRIPT)));
        RENDER_FUNCTIONS.put(
                "svelte",
                List.of(
                        new FunctionSignature("new App(", SearchTarget.SCRIPT),
                        new FunctionSignature("__svelte", SearchTarget.SCRIPT)));
    }

    static final Map<String, List<String>> SCRIPT_TYPE_PATTERNS = new LinkedHashMap<>();

    static {
        SCRIPT_TYPE_PATTERNS.put(
                "handlebars", List.of("text/x-handlebars", "text/x-handlebars-template"));
        SCRIPT_TYPE_PATTERNS.put("angular", List.of("text/ng-template"));
        SCRIPT_TYPE_PATTERNS.put("vue", List.of("text/x-template"));
        SCRIPT_TYPE_PATTERNS.put("underscore", List.of("text/template"));
        SCRIPT_TYPE_PATTERNS.put("tmpl", List.of("text/x-jquery-tmpl"));
        SCRIPT_TYPE_PATTERNS.put(
                "mustache", List.of("text/x-mustache", "text/x-mustache-template"));
        SCRIPT_TYPE_PATTERNS.put("icanhaz", List.of("text/html"));
        SCRIPT_TYPE_PATTERNS.put("hogan", List.of("text/html"));
        SCRIPT_TYPE_PATTERNS.put("ember", List.of("text/x-handlebars", "text/x-ember-template"));
    }

    static final Map<String, List<String>> TEMPLATE_ATTR_PATTERNS = new LinkedHashMap<>();

    static {
        TEMPLATE_ATTR_PATTERNS.put(
                "angular",
                List.of(
                        "ng-app",
                        "ng-controller",
                        "ng-model",
                        "ng-bind",
                        "ng-repeat",
                        "ng-if",
                        "ng-show",
                        "ng-hide",
                        "ng-class",
                        "ng-click"));
        TEMPLATE_ATTR_PATTERNS.put(
                "vue",
                List.of(
                        "v-bind", "v-model", "v-if", "v-else", "v-for", "v-on", "v-show", "v-html",
                        "v-text", ":class", "@click"));
        TEMPLATE_ATTR_PATTERNS.put(
                "mavo",
                List.of("mv-app", "mv-multiple", "mv-storage", "mv-output", "mv-attribute"));
        TEMPLATE_ATTR_PATTERNS.put(
                "alpine",
                List.of(
                        "x-data",
                        "x-bind",
                        "x-on",
                        "x-show",
                        "x-if",
                        "x-for",
                        "x-text",
                        "x-html",
                        "x-model",
                        "x-ref",
                        "x-effect",
                        "x-ignore",
                        "x-transition",
                        "x-cloak",
                        "@click",
                        ":class"));
        TEMPLATE_ATTR_PATTERNS.put(
                "ember", List.of("data-ember-action", "ember-view", "data-bindattr-"));
        TEMPLATE_ATTR_PATTERNS.put("svelte", List.of("data-svelte-h", "svelte-"));
    }

    public record PayloadDefinition(
            String engineName, String payload, String expectedResult, PayloadKind kind) {

        public boolean supportsUniqueOperands() {
            return kind == PayloadKind.MATH;
        }

        public PayloadDefinition withOperand(int operand) {
            if (!supportsUniqueOperands()) {
                return this;
            }
            String operandText = Integer.toString(operand);
            return new PayloadDefinition(
                    engineName,
                    payload.replace(Integer.toString(PROBE_OPERAND), operandText),
                    Long.toString((long) operand * operand),
                    kind);
        }
    }

    public enum PayloadKind {
        MATH,
        OBJECT
    }

    static final Map<String, PayloadDefinition> PAYLOAD_DEFINITIONS = new LinkedHashMap<>();

    static {
        registerMathPayload("angular", "{{11111*11111}}");
        registerMathPayload("vue", "{{11111*11111}}");
        registerMathPayload("mavo", "[11111*11111]");
        registerObjectPayload("handlebars", "{{this}}");
        registerMathPayload("regular", "{{11111*11111}}");
        registerMathPayload("template7", "{{11111*11111}}");
        registerMathPayload("ejs", "<%= 11111 * 11111 %>");
        registerMathPayload("marko", "${11111 * 11111}");
        registerMathPayload("tmpl", "${11111 * 11111}");
        registerMathPayload("ember", "{{11111*11111}}");
        registerMathPayload("jsrender", "{{:11111 * 11111}}");
        registerMathPayload("dot", "{{=11111 * 11111}}");
        registerMathPayload("art-template", "{{11111 * 11111}}");
        registerObjectPayload("tempo", "{{this}}");
        registerMathPayload("transparency", "{{11111 * 11111}}");
        registerMathPayload("svelte", "{11111 * 11111}");
        registerMathPayload("underscore", "<%= 11111 * 11111 %>");
        registerMathPayload("lit", "${11111 * 11111}");
        registerObjectPayload("mustache", "{{this}}");
        registerMathPayload("hogan", "{{11111*11111}}");
        registerMathPayload("twig", "{{11111*11111}}");
        registerObjectPayload("markup", "{{this}}");
        registerObjectPayload("dust", "{.}");
        registerMathPayload("nunjucks", "{{11111*11111}}");
        registerMathPayload("pug", "#{11111 * 11111}");
        registerObjectPayload("loadTemplate", "{{this}}");
        registerMathPayload("pure", "${11111 * 11111}");
        registerMathPayload("squirrelly", "{{11111 * 11111}}");
        registerMathPayload("swig", "{{11111*11111}}");
        registerMathPayload("icanhaz", "{{11111*11111}}");
        registerMathPayload("micro-template", "<%= 11111 * 11111 %>");
        registerMathPayload("juicer", "${11111 * 11111}");
        registerMathPayload("alpine", "{{11111*11111}}");
    }

    private static final String GLOBAL_PROBE_PAYLOAD =
            "try {"
                    + "  var parts = String(arguments[0]).split('.');"
                    + "  var obj = window;"
                    + "  for (var i = 0; i < parts.length; i++) {"
                    + "    if (obj == null || obj === undefined) return false;"
                    + "    obj = obj[parts[i]];"
                    + "  }"
                    + "  return obj !== undefined && obj !== null;"
                    + "} catch (e) { return false; }";

    private static final String FUNCTION_CALL_PAYLOAD =
            "try {"
                    + "  var scripts = document.querySelectorAll('script:not([src])');"
                    + "  var src = '';"
                    + "  for (var i = 0; i < scripts.length; i++) {"
                    + "    src += scripts[i].textContent + '\\n';"
                    + "  }"
                    + "  return JSON.stringify({"
                    + "    script: src,"
                    + "    html: document.documentElement.outerHTML"
                    + "  });"
                    + "} catch(e) { return '{}'; }";

    private static final String SCRIPT_TYPE_PAYLOAD =
            "try {"
                    + "  var tags = document.querySelectorAll('script[type]');"
                    + "  var types = [];"
                    + "  for (var i = 0; i < tags.length; i++) {"
                    + "    var t = tags[i].getAttribute('type');"
                    + "    if (t && types.indexOf(t) === -1) types.push(t);"
                    + "  }"
                    + "  return types.join('\\n');"
                    + "} catch(e) { return ''; }";

    private static final String TEMPLATE_ATTR_PAYLOAD =
            "try {"
                    + "  var seen = {};"
                    + "  var all = document.querySelectorAll('*');"
                    + "  for (var i = 0; i < all.length; i++) {"
                    + "    var attrs = all[i].attributes;"
                    + "    for (var j = 0; j < attrs.length; j++) {"
                    + "      seen[attrs[j].name] = true;"
                    + "    }"
                    + "  }"
                    + "  return Object.keys(seen).join('\\n');"
                    + "} catch(e) { return ''; }";

    private static void registerMathPayload(String engineName, String payload) {
        registerPayload(engineName, payload, PROBE_EXPECTED_RESULT, PayloadKind.MATH);
    }

    private static void registerObjectPayload(String engineName, String payload) {
        registerPayload(engineName, payload, "[object Object]", PayloadKind.OBJECT);
    }

    private static void registerPayload(
            String engineName, String payload, String expectedResult, PayloadKind kind) {
        PAYLOAD_DEFINITIONS.put(
                engineName, new PayloadDefinition(engineName, payload, expectedResult, kind));
    }

    public record DetectionResult(
            String engineName,
            String globalExpression,
            List<String> matchedCalls,
            List<String> matchedScriptTypes,
            List<String> matchedTemplateAttrs) {

        public DetectionResult(String engineName, String globalExpression) {
            this(engineName, globalExpression, List.of(), List.of(), List.of());
        }

        public DetectionResult(
                String engineName, String globalExpression, List<String> matchedCalls) {
            this(engineName, globalExpression, matchedCalls, List.of(), List.of());
        }

        public boolean detected() {
            return !"unknown".equals(engineName);
        }

        public boolean hasActiveCalls() {
            return !matchedCalls.isEmpty();
        }

        public boolean hasTagEvidence() {
            return !matchedScriptTypes.isEmpty() || !matchedTemplateAttrs.isEmpty();
        }

        @Override
        public String toString() {
            if (!detected()) return "engine=unknown";
            String calls = matchedCalls.isEmpty() ? "none" : String.join(", ", matchedCalls);
            String stypes =
                    matchedScriptTypes.isEmpty() ? "none" : String.join(", ", matchedScriptTypes);
            String attrs =
                    matchedTemplateAttrs.isEmpty()
                            ? "none"
                            : String.join(", ", matchedTemplateAttrs);
            return String.format(
                    "engine=%-15s  global=%s  activeCalls=[%s]  scriptTypes=[%s]  templateAttrs=[%s]",
                    engineName, globalExpression, calls, stypes, attrs);
        }
    }

    public static DetectionResult detect(WebDriver driver, String url) {
        if (driver == null) return unknown();

        try {
            driver.get(url);
            waitForPageToSettle(driver);
        } catch (Exception e) {
            LOGGER.warn(
                    "CSTI: failed to load '{}' for engine detection ({}): {}",
                    url,
                    e.getClass().getSimpleName(),
                    e.getMessage());
            return unknown();
        }

        JavascriptExecutor js = (JavascriptExecutor) driver;

        String detectedEngine = null;
        String detectedGlobal = null;

        for (Map.Entry<String, String> entry : TEMPLATES.entrySet()) {
            try {
                if (evalGlobal(js, entry.getValue())) {
                    detectedEngine = entry.getKey();
                    detectedGlobal = entry.getValue();
                    LOGGER.info(
                            "CSTI: engine '{}' detected via global '{}'",
                            detectedEngine,
                            detectedGlobal);
                    break;
                }
            } catch (Exception ignored) {
            }
        }

        if (detectedEngine == null) {
            LOGGER.warn("CSTI: no engine detected for {}", url);
            return unknown();
        }

        List<String> matchedCalls = scanForFunctionCalls(js, detectedEngine);
        if (matchedCalls.isEmpty()) {
            LOGGER.info(
                    "CSTI: global '{}' present but no active render calls found for {}",
                    detectedGlobal,
                    url);
        } else {
            LOGGER.info(
                    "CSTI: active render calls confirmed for '{}': {}",
                    detectedEngine,
                    matchedCalls);
        }

        List<String> matchedScriptTypes = scanForScriptTypes(js, detectedEngine);
        if (matchedScriptTypes.isEmpty()) {
            LOGGER.info(
                    "CSTI: no script-type template blocks found for engine '{}' at {}",
                    detectedEngine,
                    url);
        } else {
            LOGGER.info(
                    "CSTI: script-type template blocks confirmed for '{}': {}",
                    detectedEngine,
                    matchedScriptTypes);
        }

        List<String> matchedTemplateAttrs = scanForTemplateAttributes(js, detectedEngine);
        if (matchedTemplateAttrs.isEmpty()) {
            LOGGER.info(
                    "CSTI: no custom template attributes found for engine '{}' at {}",
                    detectedEngine,
                    url);
        } else {
            LOGGER.info(
                    "CSTI: custom template attributes confirmed for '{}': {}",
                    detectedEngine,
                    matchedTemplateAttrs);
        }

        return new DetectionResult(
                detectedEngine,
                detectedGlobal,
                matchedCalls,
                matchedScriptTypes,
                matchedTemplateAttrs);
    }

    public static boolean isTagHeuristicApplicable(String engine) {
        if (engine == null || engine.isBlank() || "unknown".equals(engine)) {
            return false;
        }
        List<String> scriptPatterns = SCRIPT_TYPE_PATTERNS.get(engine);
        if (scriptPatterns != null && !scriptPatterns.isEmpty()) {
            return true;
        }
        List<String> attrPatterns = TEMPLATE_ATTR_PATTERNS.get(engine);
        return attrPatterns != null && !attrPatterns.isEmpty();
    }

    public static PayloadDefinition getPayloadDefinition(String engine) {
        return PAYLOAD_DEFINITIONS.get(engine);
    }

    private static boolean evalGlobal(JavascriptExecutor js, String global) {
        Object result = js.executeScript(GLOBAL_PROBE_PAYLOAD, global);
        return Boolean.TRUE.equals(result);
    }

    private static List<String> scanForFunctionCalls(JavascriptExecutor js, String engine) {
        List<String> found = new ArrayList<>();

        List<FunctionSignature> signatures = RENDER_FUNCTIONS.get(engine);
        if (signatures == null || signatures.isEmpty()) {
            LOGGER.debug("CSTI: no function signatures registered for engine '{}'", engine);
            return found;
        }

        String scriptCorpus = "";
        String htmlCorpus = "";
        try {
            Object raw = js.executeScript(FUNCTION_CALL_PAYLOAD);
            if (raw instanceof String json && !json.isBlank()) {
                JsonNode node = JSON.readTree(json);
                scriptCorpus = node.path("script").asText("");
                htmlCorpus = node.path("html").asText("");
            }
        } catch (Exception e) {
            LOGGER.warn("CSTI: failed to collect page sources: {}", e.getMessage());
            return found;
        }

        for (FunctionSignature sig : signatures) {
            String corpus = (sig.target() == SearchTarget.HTML) ? htmlCorpus : scriptCorpus;
            if (corpus.contains(sig.signature())) {
                LOGGER.debug(
                        "CSTI: matched signature '{}' in {} corpus", sig.signature(), sig.target());
                found.add(sig.signature());
            }
        }

        return found;
    }

    private static List<String> scanForScriptTypes(JavascriptExecutor js, String engine) {
        List<String> found = new ArrayList<>();

        List<String> patterns = SCRIPT_TYPE_PATTERNS.get(engine);
        if (patterns == null || patterns.isEmpty()) {
            LOGGER.debug("CSTI: no script-type patterns registered for engine '{}'", engine);
            return found;
        }

        String corpus = "";
        try {
            Object raw = js.executeScript(SCRIPT_TYPE_PAYLOAD);
            if (raw instanceof String s && !s.isBlank()) corpus = s;
        } catch (Exception e) {
            LOGGER.warn("CSTI: failed to collect script type attributes: {}", e.getMessage());
            return found;
        }

        if (corpus.isBlank()) return found;

        for (String typeValue : corpus.split("\n")) {
            String normalised = typeValue.trim().toLowerCase(Locale.ROOT);
            if (normalised.isBlank()) continue;

            for (String pattern : patterns) {
                if (normalised.contains(pattern.toLowerCase(Locale.ROOT))
                        && !found.contains(typeValue)) {
                    LOGGER.debug(
                            "CSTI:  script type '{}' matched pattern '{}'", typeValue, pattern);
                    found.add(typeValue);
                    break;
                }
            }
        }

        return found;
    }

    private static List<String> scanForTemplateAttributes(JavascriptExecutor js, String engine) {
        List<String> found = new ArrayList<>();

        List<String> patterns = TEMPLATE_ATTR_PATTERNS.get(engine);
        if (patterns == null || patterns.isEmpty()) {
            LOGGER.debug("CSTI: no template-attribute patterns registered for engine '{}'", engine);
            return found;
        }

        String corpus = "";
        try {
            Object raw = js.executeScript(TEMPLATE_ATTR_PAYLOAD);
            if (raw instanceof String s && !s.isBlank()) corpus = s;
        } catch (Exception e) {
            LOGGER.warn("CSTI:  failed to enumerate DOM attributes: {}", e.getMessage());
            return found;
        }

        if (corpus.isBlank()) return found;

        for (String rawAttr : corpus.split("\n")) {
            String attrName = rawAttr.trim().toLowerCase(Locale.ROOT);
            if (attrName.isBlank() || found.contains(attrName)) continue;

            for (String pattern : patterns) {
                String normPattern = pattern.toLowerCase(Locale.ROOT);

                boolean matched =
                        normPattern.endsWith("-")
                                ? attrName.startsWith(normPattern)
                                : attrName.contains(normPattern);

                if (matched) {
                    LOGGER.debug("CSTI: attribute '{}' matched pattern '{}'", attrName, pattern);
                    found.add(attrName);
                    break;
                }
            }
        }

        return found;
    }

    private static DetectionResult unknown() {
        return new DetectionResult("unknown", "");
    }
}
