/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.addon.commonlib.http;

import static org.apache.commons.lang.StringEscapeUtils.escapeHtml;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.Source;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Object that represent one response and has utilities to compare it with others
 *
 * @author DiogoMRSilva (2018). Credits: the heuristics used to compare 2 responses are the same as
 *     those from Backslash Powered Scanner by James Kettle, but the implementation and its usage is
 *     independent. https://github.com/PortSwigger/backslash-powered-scanner
 * @since 1.8.0
 */
public class ComparableResponse {

    private static final float STATUS_CODE_WEIGHT = 1;
    private static final float HEADERS_WEIGHT = 0.15f;
    private static final float HTML_STRUCTURE_WEIGHT = 0.5f;
    private static final float NUMBER_LINES_WEIGHT = 0.25f;
    private static final float NUMBER_WORDS_WEIGHT = 0.5f;
    private static final float REFLECTION_WEIGHT = 0.5f;
    private static final float RELEVANT_KEYWORDS_WEIGHT = 0.5f;
    private static final List<String> DYNAMIC_HEADERS = Arrays.asList("Expires", "Date");
    private static final List<String> RELEVANT_KEYWORDS =
            Arrays.asList(
                    "error",
                    "problem",
                    "unexpected",
                    "template",
                    "line",
                    "syntax",
                    "warning",
                    "unknown",
                    "token");

    private static final String CONTENT_TYPE_HTML = "text/html";
    private static final String CONTENT_TYPE_JSON = "json";
    private static final Pattern CRLF_SPLIT_PATTERN = Pattern.compile("\r\n|\r|\n");
    private static final Pattern WORD_SPLIT_PATTERN = Pattern.compile("\\s+");
    private static final Pattern CONTENT_TYPE_SPLIT_PATTERN = Pattern.compile(";");

    private int statusCode;
    private String body;
    private Map<String, String> headers;
    private String valueSent;
    private Map<String, Integer> allPaths;
    private int numPaths;

    // Use variables instead of constants to be able to tune it depending on the differences on
    // normal request replay.
    private float statusCodeWeight = STATUS_CODE_WEIGHT;
    private float headersWeight = HEADERS_WEIGHT;
    private float bodyStructureWeight = HTML_STRUCTURE_WEIGHT;
    private float numberLinesWeight = NUMBER_LINES_WEIGHT;
    private float numberWordsWeight = NUMBER_WORDS_WEIGHT;
    private float reflectionWeight = REFLECTION_WEIGHT;
    private float relevantKeywordsWeight = RELEVANT_KEYWORDS_WEIGHT;

    public ComparableResponse(
            int statusCode, String body, Map<String, String> headers, String valueSent) {
        this.statusCode = statusCode;
        this.body = body;
        this.headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        this.headers.putAll(headers);
        this.valueSent = valueSent;
    }

    /**
     * Constructs a {@code ComparableResponse} from the given {@code HttpMessage}. If the payload
     * (or valueSent) is null it will be treated as empty string internally.
     *
     * @param httpMessage The {@code HttpMessage} from which to create the {@code
     *     ComparableResponse}
     * @param valueSent the payload sent (if any) applicable to the response being analyzed.
     */
    public ComparableResponse(HttpMessage httpMessage, String valueSent) {
        this.statusCode = httpMessage.getResponseHeader().getStatusCode();
        this.body = httpMessage.getResponseBody().toString();
        this.valueSent = valueSent == null ? "" : valueSent;
        this.headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        List<HttpHeaderField> headersObjects = httpMessage.getResponseHeader().getHeaders();

        for (HttpHeaderField header : headersObjects) {
            this.headers.put(header.getName(), header.getValue());
        }
    }

    /** @return the status code */
    public int getStatusCode() {
        return statusCode;
    }

    /** @return the body */
    public String getBody() {
        return body;
    }

    /** @return the headers */
    public Map<String, String> getHeaders() {
        return headers;
    }

    /** @return the valueSent */
    public String getValueSent() {
        return valueSent;
    }

    /**
     * Compare this {@code ComparableResponse} with another based on heuristics. 0 means very
     * different and 1 very similar.
     *
     * @param otherResponse the response to compare with this one
     */
    public float compareWith(ComparableResponse otherResponse) {
        float total = 1f;
        // compare the status code
        total *=
                statusCodeHeuristic(this, otherResponse) * statusCodeWeight
                        + (1 - statusCodeWeight);
        if (total == 0) {
            return 0f;
        }
        // compare the body HTML
        total *=
                bodyTreesStructureHeuristic(this, otherResponse) * bodyStructureWeight
                        + (1 - bodyStructureWeight);

        // compare headers
        total *= headersCompareHeuristic(this, otherResponse) * headersWeight + (1 - headersWeight);

        // compare number of lines
        total *=
                lineCountHeuristic(this, otherResponse) * numberLinesWeight
                        + (1 - numberLinesWeight);

        // compare number of words
        total *=
                wordCountHeuristic(this, otherResponse) * numberWordsWeight
                        + (1 - numberWordsWeight);

        // compare reflections in normal state and HTML encoded
        total *=
                inputReflectionHeuristic(this, otherResponse) * reflectionWeight
                        + (1 - reflectionWeight);

        // compare the number relevant keywords
        total *=
                relevantKeywordsCountHeuristic(this, otherResponse) * relevantKeywordsWeight
                        + (1 - relevantKeywordsWeight);

        return total;
    }

    /**
     * Tune heuristics weights based on message that should be similar. It reduce the weight of
     * heuristics that have low similarity between the original response and the reference response.
     *
     * @param referenceResponse the response to compare with, one that should have similar results.
     */
    public void tuneHeuristicsWithResponse(ComparableResponse referenceResponse) {
        bodyStructureWeight =
                bodyTreesStructureHeuristic(this, referenceResponse) * bodyStructureWeight;
        headersWeight = headersCompareHeuristic(this, referenceResponse) * headersWeight;
        numberLinesWeight = lineCountHeuristic(this, referenceResponse) * numberLinesWeight;
        numberWordsWeight = wordCountHeuristic(this, referenceResponse) * numberWordsWeight;
        reflectionWeight = inputReflectionHeuristic(this, referenceResponse) * reflectionWeight;
        relevantKeywordsWeight =
                relevantKeywordsCountHeuristic(this, referenceResponse) * relevantKeywordsWeight;
    }

    /**
     * Compares two responses.
     *
     * @param response1 The response to compare with response2
     * @param response2 The response compare with response1
     */
    public static float compareMessages(
            ComparableResponse response1, ComparableResponse response2) {
        return response1.compareWith(response2);
    }

    /**
     * Return a heuristic evaluation between the status code of the 2 responses. 0 means very
     * different and 1 very similar.
     *
     * @param response1 The first response to compare
     * @param response2 The second response to compare
     */
    public static float statusCodeHeuristic(
            ComparableResponse response1, ComparableResponse response2) {
        return response1.statusCode != response2.statusCode ? 0f : 1f;
    }

    /**
     * Return a heuristic evaluation between the number relevant keywords in the 2 responses. 0
     * means very different and 1 very similar.
     *
     * @param response1 The first response to compare
     * @param response2 The second response to compare
     */
    public static float relevantKeywordsCountHeuristic(
            ComparableResponse response1, ComparableResponse response2) {
        float nRelevantKeywordsR1 = 0;
        float nRelevantKeywordsR2 = 0;
        for (String keyword : RELEVANT_KEYWORDS) {
            if (keyword.equalsIgnoreCase(response1.getValueSent())
                    || keyword.equalsIgnoreCase(response2.getValueSent())) {
                continue;
            }
            nRelevantKeywordsR1 +=
                    StringUtils.countMatches(response1.body.toLowerCase(), keyword.toLowerCase());
            nRelevantKeywordsR2 +=
                    StringUtils.countMatches(response2.body.toLowerCase(), keyword.toLowerCase());
        }

        if (nRelevantKeywordsR1 > nRelevantKeywordsR2) {
            return nRelevantKeywordsR2 / nRelevantKeywordsR1;
        }
        if (nRelevantKeywordsR1 < nRelevantKeywordsR2) {
            return nRelevantKeywordsR1 / nRelevantKeywordsR2;
        }

        return 1f;
    }

    /**
     * Return a heuristic evaluation the number of reflections in the 2 responses. 0 means very
     * different and 1 very similar.
     *
     * @param response1 The first response to compare
     * @param response2 The second response to compare
     */
    public static float inputReflectionHeuristic(
            ComparableResponse response1, ComparableResponse response2) {
        String req1Value = response1.getValueSent();
        String req2Value = response2.getValueSent();
        String bodyResp1 = response1.body;
        String bodyResp2 = response2.body;

        int nReflectionsPayload1in1 = StringUtils.countMatches(bodyResp1, req1Value);
        nReflectionsPayload1in1 += StringUtils.countMatches(bodyResp1, escapeHtml(req1Value));
        int nReflectionsPayload2in2 = StringUtils.countMatches(bodyResp2, req2Value);
        nReflectionsPayload2in2 += StringUtils.countMatches(bodyResp2, escapeHtml(req2Value));

        // In case one payload is a substring of the other it will appear but it is not fixed
        // so we need to remove the payload from the body to know the ones that are independent
        if (req2Value.contains(req1Value)) {
            bodyResp2 = bodyResp2.replace(req2Value, "");
        }
        int nReflectionsPayload1in2 = StringUtils.countMatches(bodyResp2, req1Value);
        if (!escapeHtml(req1Value).equals(req1Value)) {
            nReflectionsPayload1in2 += StringUtils.countMatches(bodyResp2, escapeHtml(req1Value));
        }
        if (req1Value.contains(req2Value)) {
            bodyResp1 = bodyResp1.replace(req1Value, "");
        }
        int nReflectionsPayload2in1 = StringUtils.countMatches(bodyResp1, req2Value);
        if (!escapeHtml(req2Value).equals(req2Value)) {
            nReflectionsPayload2in1 += StringUtils.countMatches(bodyResp1, escapeHtml(req2Value));
        }
        float nNonPersistentReflectionsPayload1 =
                (float) 1 + Math.abs(nReflectionsPayload1in1 - nReflectionsPayload1in2);
        float nNonPersistentReflectionsPayload2 =
                (float) 1 + Math.abs(nReflectionsPayload2in1 - nReflectionsPayload2in2);

        if (nNonPersistentReflectionsPayload1 > nNonPersistentReflectionsPayload2) {
            return nNonPersistentReflectionsPayload2 / nNonPersistentReflectionsPayload1;
        }
        if (nNonPersistentReflectionsPayload1 < nNonPersistentReflectionsPayload2) {
            return nNonPersistentReflectionsPayload1 / nNonPersistentReflectionsPayload2;
        }
        return 1f;
    }

    /**
     * Return a heuristic evaluation between the number of words of the 2 responses. 0 means very
     * different and 1 very similar.
     *
     * @param response1 The first response to compare
     * @param response2 The second response to compare
     */
    public static float wordCountHeuristic(
            ComparableResponse response1, ComparableResponse response2) {
        float nWords1 = WORD_SPLIT_PATTERN.split(response1.body).length;
        float nWords2 = WORD_SPLIT_PATTERN.split(response2.body).length;

        if (nWords1 > nWords2) {
            return nWords2 / nWords1;
        }
        if (nWords1 < nWords2) {
            return nWords1 / nWords2;
        }
        return 1f;
    }

    /**
     * Return a heuristic evaluation between the number of lines of the 2 responses. 0 means very
     * different and 1 very similar.
     *
     * @param response1 The first response to compare
     * @param response2 The second response to compare
     */
    public static float lineCountHeuristic(
            ComparableResponse response1, ComparableResponse response2) {
        float nLinesR1 = CRLF_SPLIT_PATTERN.split(response1.body).length;
        float nLinesR2 = CRLF_SPLIT_PATTERN.split(response2.body).length;

        if (nLinesR1 > nLinesR2) {
            return nLinesR2 / nLinesR1;
        }
        if (nLinesR1 < nLinesR2) {
            return nLinesR1 / nLinesR2;
        }
        return 1f;
    }

    /**
     * Return a heuristic evaluation between the 2 Responses headers. 0 means very different and 1
     * very similar.
     *
     * @param response1 The first response to compare
     * @param response2 The second response to compare
     */
    public static float headersCompareHeuristic(
            ComparableResponse response1, ComparableResponse response2) {
        if (response1.headers.isEmpty() && response2.headers.isEmpty()) {
            return 1; // Both empty, equal
        }
        if (response1.headers.isEmpty() || response2.headers.isEmpty()) {
            return 0; // One empty, very different
        }
        float equalHeadersContent = 0;
        int r1HeaderCount = response1.headers.keySet().size();
        int r2HeaderCount = response2.headers.keySet().size();
        float numberHeaders = r1HeaderCount > r2HeaderCount ? r1HeaderCount : r2HeaderCount;
        Map<String, String> larger = response1.headers;
        Map<String, String> smaller = response2.headers;
        if (r2HeaderCount > r1HeaderCount) {
            larger = response2.headers;
            smaller = response1.headers;
        }

        for (Entry<String, String> entry : larger.entrySet()) {
            if (DYNAMIC_HEADERS.contains(entry.getKey())) {
                numberHeaders = numberHeaders - 1;
                continue;
            }
            if (smaller.containsKey(entry.getKey())
                    && (smaller.get(entry.getKey()).equals(larger.get(entry.getKey())))) {
                equalHeadersContent += 1;
            }
        }
        // Similar to (equalHeaders / numberHeaders * equalHeadersContent / equalHeaders)* 0.25 +
        // 0.75;
        return equalHeadersContent / numberHeaders;
    }

    /**
     * Return a heuristic evaluation between Body structure of the 2 responses. 0 means very
     * different and 1 very similar.
     *
     * @param response1 The first response to compare
     * @param response2 The second response to compare
     */
    public static float bodyTreesStructureHeuristic(
            ComparableResponse response1, ComparableResponse response2) {
        String r1ContentType = getContentType(response1);
        String r2ContentType = getContentType(response2);

        if (r1ContentType != null && r2ContentType != null) {
            // We just want the type
            // TODO should I consider different if they have different parameters?
            // as "text/html; charset=utf-8" and "text/html
            if (!r1ContentType.equals(r2ContentType)) {
                return 0;
            }
            if (r1ContentType.contains(CONTENT_TYPE_HTML)
                    || r1ContentType.contains(CONTENT_TYPE_JSON)) {
                Map<String, Integer> response1paths = response1.getAllPaths();
                Map<String, Integer> response2paths = response2.getAllPaths();

                if (response1.numPaths == 0 && response2.numPaths == 0) {
                    return 1;
                }
                if (response1.numPaths == 0 || response2.numPaths == 0) {
                    return 0;
                }

                int numberOfCommonPaths = 0;
                for (Map.Entry<String, Integer> entry : response1paths.entrySet()) {
                    String path = entry.getKey();
                    if (entry.getValue().equals(response2paths.get(path))) {
                        numberOfCommonPaths += entry.getValue();
                    }
                }

                float fractionOfMatch1 = (float) numberOfCommonPaths / response1.numPaths;
                float fractionOfMatch2 = (float) numberOfCommonPaths / response2.numPaths;

                return (fractionOfMatch1 + fractionOfMatch2) / 2;
            }
            // Other comparable content types may exist
            return 1;
        }

        // Case none of the responses contain Content-Type header
        if (r1ContentType == null && r2ContentType == null) {
            return 1;
        }
        // Case one response contain Content-Type header and the other doesn't
        return 0;
    }

    /** @return all The Possible Paths. */
    private Map<String, Integer> getAllPaths() {
        synchronized (this) {
            if (allPaths == null) {
                allPaths = new HashMap<>();
                numPaths = 0;
                String contentType = getContentType(this);
                if (contentType == null) {
                    return allPaths;
                }
                if (contentType.contains(CONTENT_TYPE_HTML)) {
                    Source parsedBody = new Source(body);
                    for (Element child : parsedBody.getChildElements()) {
                        for (String childPath : getHtmlElementPaths(child)) {
                            allPaths.merge(childPath, 1, Integer::sum);
                            numPaths++;
                        }
                    }
                }
                if (contentType.contains(CONTENT_TYPE_JSON)) {
                    JSONObject jsonBody = JSONObject.fromObject(body);
                    for (String childPath : getJsonElementPaths(jsonBody)) {
                        allPaths.merge(childPath, 1, Integer::sum);
                        numPaths++;
                    }
                }
            }
        }
        return allPaths;
    }

    /**
     * Get all possible paths of HTML tags.
     *
     * @param node to extract paths
     */
    private List<String> getHtmlElementPaths(Element node) {
        List<String> listOfPaths = new ArrayList<>();
        for (Element child : node.getChildElements()) {
            for (String childPath : getHtmlElementPaths(child)) {
                listOfPaths.add(childPath.concat(node.getName()));
            }
        }
        if (listOfPaths.isEmpty()) {
            listOfPaths.add(node.getName());
        }

        return listOfPaths;
    }

    /**
     * Get all possible paths of JSON tags.
     *
     * @param elementObject to extract paths
     */
    private List<String> getJsonElementPaths(Object elementObject) {
        List<String> listOfPaths = new ArrayList<>();
        if (elementObject instanceof JSONObject) {

            JSONObject jsonObject = (JSONObject) elementObject;

            Iterator<?> jsonBodyElements = jsonObject.keys();

            while (jsonBodyElements.hasNext()) {
                String childJsonName = (String) jsonBodyElements.next();
                Object childJson = jsonObject.get(childJsonName);
                for (String childPath : getJsonElementPaths(childJson)) {
                    listOfPaths.add(childPath.concat(childJsonName));
                }
            }
        } else if (elementObject instanceof JSONArray) {

            JSONArray jsonArray = (JSONArray) elementObject;

            for (Object child : jsonArray) {
                for (String childPath : getJsonElementPaths(child)) {
                    listOfPaths.add(childPath);
                }
            }
        }

        if (listOfPaths.isEmpty()) {
            listOfPaths.add("");
        }

        return listOfPaths;
    }

    private static String getContentType(ComparableResponse compResp) {
        String ctHeader = compResp.getHeaders().get(HttpHeader.CONTENT_TYPE);
        return ctHeader != null
                ? CONTENT_TYPE_SPLIT_PATTERN.split(ctHeader.toLowerCase(Locale.ROOT))[0]
                : null;
    }
}
