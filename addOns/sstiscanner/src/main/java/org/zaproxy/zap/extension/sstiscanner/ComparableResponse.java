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
package org.zaproxy.zap.extension.sstiscanner;

import static org.apache.commons.lang.StringEscapeUtils.escapeHtml;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.Source;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Object that represent one response and has utilities to compare it with others
 *
 * @author DiogoMRSilva (2018). Credits: the heuristics used to compare 2 responses are the same as
 *     the ones Backslash Powered Scanner by James Kettle, but the implementation and its usage is
 *     independent. https://github.com/PortSwigger/backslash-powered-scanner
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

    private int statusCode;
    private String body;
    private Map<String, String> headers;
    private String valueSent;
    private HashMap<String, Integer> allPaths = null;
    private int numPaths = 0;

    // use variables instead of constants to be able to tune it depending on the differences on
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
        this.headers = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);
        this.headers.putAll(headers);
        this.valueSent = valueSent;
    }

    public ComparableResponse(HttpMessage httpMessage, String valueSent) {
        this.statusCode = httpMessage.getResponseHeader().getStatusCode();
        this.body = new String(httpMessage.getResponseBody().getBytes());
        this.valueSent = valueSent;
        this.headers = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);
        List<HttpHeaderField> headersObjects = httpMessage.getResponseHeader().getHeaders();

        for (HttpHeaderField header : headersObjects) {
            if (header == null) {
                break;
            }
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
     * Compare message with other based on heuristics
     *
     * @param otherResponse the response to compare with this one
     */
    public float compareWith(ComparableResponse otherResponse) {
        float total = 1f;
        // compare the status code
        total *=
                statusCodeHeuristic(this, otherResponse) * statusCodeWeight
                        + (1 - statusCodeWeight);
        if (total == 0) return 0f;

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
     * heuristics that have low similarity between the original response and the referenceResponse
     *
     * @param referenceResponse the response to compare with this one that should have similar
     *     results.
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
     * Compare response1 with response2
     *
     * @param response1 to compare with response2
     * @param response2 to compare with response1
     */
    public static float compareMessages(
            ComparableResponse response1, ComparableResponse response2) {
        return response1.compareWith(response2);
    }

    /**
     * Return an heuristic evaluation between the status code of the 2 responses . 0 means very
     * different and 1 very similar
     *
     * @param response1 response to compare
     * @param response2 response to compare
     */
    public static float statusCodeHeuristic(
            ComparableResponse response1, ComparableResponse response2) {
        return ((response1.statusCode != response2.statusCode) ? 0f : 1f);
    }

    /**
     * Return an heuristic evaluation between the number relevant keywords in the 2 responses. 0
     * means very different and 1 very similar
     *
     * @param response1 response to compare
     * @param response2 response to compare
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
        } else if (nRelevantKeywordsR1 < nRelevantKeywordsR2) {
            return nRelevantKeywordsR1 / nRelevantKeywordsR2;
        }

        return 1f;
    }

    /**
     * Return an heuristic evaluation the number of reflections in the 2 responses. 0 means very
     * different and 1 very similar
     *
     * @param response1 response to compare
     * @param response2 response to compare
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

        // in case one payload1 is substring of the other it will appear but  it is not fixed
        // so we need to remove the payload2 from the body to know the ones that are independent
        if (req2Value.contains(req1Value)) bodyResp2 = bodyResp2.replace(req2Value, "");
        int nReflectionsPayload1in2 = StringUtils.countMatches(bodyResp2, req1Value);
        if (!escapeHtml(req1Value).equals(req1Value))
            nReflectionsPayload1in2 += StringUtils.countMatches(bodyResp2, escapeHtml(req1Value));

        if (req1Value.contains(req2Value)) bodyResp1 = bodyResp1.replace(req1Value, "");
        int nReflectionsPayload2in1 = StringUtils.countMatches(bodyResp1, req2Value);
        if (!escapeHtml(req2Value).equals(req2Value))
            nReflectionsPayload2in1 += StringUtils.countMatches(bodyResp1, escapeHtml(req2Value));

        float nNonPersistentReflectionsPayload1 =
                1 + Math.abs(nReflectionsPayload1in1 - nReflectionsPayload1in2);
        float nNonPersistentReflectionsPayload2 =
                1 + Math.abs(nReflectionsPayload2in1 - nReflectionsPayload2in2);

        if (nNonPersistentReflectionsPayload1 > nNonPersistentReflectionsPayload2)
            return nNonPersistentReflectionsPayload2 / nNonPersistentReflectionsPayload1;
        else if (nNonPersistentReflectionsPayload1 < nNonPersistentReflectionsPayload2)
            return nNonPersistentReflectionsPayload1 / nNonPersistentReflectionsPayload2;

        return 1f;
    }

    /**
     * Return an heuristic evaluation between the number of words of the 2 responses. 0 means very
     * different and 1 very similar
     *
     * @param response1 response to compare
     * @param response2 response to compare
     */
    public static float wordCountHeuristic(
            ComparableResponse response1, ComparableResponse response2) {
        float nWords1 = response1.body.split("\\s+").length;
        float nWords2 = response2.body.split("\\s+").length;

        if (nWords1 > nWords2) {
            return nWords2 / nWords1;
        } else if (nWords1 < nWords2) {
            return nWords1 / nWords2;
        }
        return 1f;
    }

    /**
     * Return an heuristic evaluation between the number of lines of the 2 responses. 0 means very
     * different and 1 very similar
     *
     * @param response1 response to compare
     * @param response2 response to compare
     */
    public static float lineCountHeuristic(
            ComparableResponse response1, ComparableResponse response2) {
        float nLinesR1 = response1.body.split("\r\n|\r|\n").length;
        float nLinesR2 = response2.body.split("\r\n|\r|\n").length;

        if (nLinesR1 > nLinesR2) {
            return nLinesR2 / nLinesR1;
        } else if (nLinesR1 < nLinesR2) {
            return nLinesR1 / nLinesR2;
        }
        return 1f;
    }

    /**
     * Return an heuristic evaluation between the 2 Responses headers. 0 means very different and 1
     * very similar
     *
     * @param response1 response to compare
     * @param response2 response to compare
     */
    public static float headersCompareHeuristic(
            ComparableResponse response1, ComparableResponse response2) {
        float equalHeadersContent = 0;
        float numberHeaders = response1.headers.keySet().size();

        for (String key : response1.headers.keySet()) {
            if (response2.getHeaders().containsKey(key)) {
                if (response2.getHeaders().get(key).equals(response1.headers.get(key))
                        || DYNAMIC_HEADERS.contains(key)) {
                    equalHeadersContent += 1;
                }
            }
        }
        // Similar to (equalHeaders / numberHeaders * equalHeadersContent / equalHeaders)* 0.25 +
        // 0.75;
        return equalHeadersContent / numberHeaders;
    }

    /**
     * Return an heuristic evaluation between Body structure of the 2 responses . 0 means very
     * different and 1 very similar
     *
     * @param response1 response to compare
     * @param response2 response to compare
     */
    public static float bodyTreesStructureHeuristic(
            ComparableResponse response1, ComparableResponse response2) {
        String r1ContentType = response1.getHeaders().get("Content-Type");
        String r2ContentType = response2.getHeaders().get("Content-Type");

        if (r1ContentType != null && r2ContentType != null) {
            // we just want the type
            // TODO should I consider different if they have different parameters?
            // as "text/html; charset=utf-8" and "text/html
            r1ContentType = r1ContentType.toLowerCase().split(";")[0];
            r2ContentType = r2ContentType.toLowerCase().split(";")[0];

            if (!r1ContentType.equals(r2ContentType)) {
                return 0;
            } else if (r1ContentType.contains("text/html") || r1ContentType.contains("json")) {
                HashMap<String, Integer> response1paths = response1.getAllPaths();
                HashMap<String, Integer> response2paths = response2.getAllPaths();

                if (response1.numPaths == 0 || response2.numPaths == 0) {
                    if (response1.numPaths != 0 || response2.numPaths != 0) {
                        return 0;
                    } else {
                        return 1;
                    }
                }

                int numberOfCommonPaths = 0;
                for (String path : response1paths.keySet()) {
                    if (response1paths.get(path).equals(response2paths.get(path))) {
                        numberOfCommonPaths += response1paths.get(path);
                    }
                }

                float fractionOfMatch1 = (float) numberOfCommonPaths / response1.numPaths;
                float fractionOfMatch2 = (float) numberOfCommonPaths / response2.numPaths;

                return (fractionOfMatch1 + fractionOfMatch2) / 2;
            } else {
                // Other comparable content types may exist
                return 1;
            }
        }

        // Case none of the responses contain Content-Type header
        else if (r1ContentType == null && r2ContentType == null) {
            return 1;
        }

        // Case one response contain Content-Type header and the other doesn't
        else {
            return 0;
        }
    }

    /** @return all The Possible Paths */
    public HashMap<String, Integer> getAllPaths() {
        synchronized (this) {
            if (allPaths == null) {
                allPaths = new HashMap<String, Integer>();
                numPaths = 0;
                if (getHeaders().get("Content-Type").toLowerCase().contains("text/html")) {
                    Source parsedBody = new Source(body);
                    for (Element child : parsedBody.getChildElements()) {
                        for (String childPath : getHTMLElementPaths(child)) {
                            allPaths.merge(childPath, 1, Integer::sum);
                            numPaths++;
                        }
                    }
                } else if (getHeaders().get("Content-Type").toLowerCase().contains("json")) {
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
     * Get all possible paths of HTML tags
     *
     * @param node to extract paths
     */
    ArrayList<String> getHTMLElementPaths(Element node) {
        ArrayList<String> listOfPaths = new ArrayList<String>();

        for (Element child : node.getChildElements()) {
            for (String childPath : getHTMLElementPaths(child)) {
                listOfPaths.add(childPath.concat(node.getName()));
            }
        }
        if (listOfPaths.size() == 0) {
            listOfPaths.add(node.getName());
        }

        return listOfPaths;
    }

    /**
     * Get all possible paths of JSON tags
     *
     * @param elementObject to extract paths
     */
    ArrayList<String> getJsonElementPaths(Object elementObject) {
        ArrayList<String> listOfLists = new ArrayList<String>();
        if (elementObject instanceof JSONObject) {

            JSONObject jsonObject = (JSONObject) elementObject;

            Iterator<?> jsonBodyElements = jsonObject.keys();

            while (jsonBodyElements.hasNext()) {
                String childJsonName = (String) jsonBodyElements.next();
                Object childJson = jsonObject.get(childJsonName);
                for (String childPath : getJsonElementPaths(childJson)) {
                    listOfLists.add(childPath.concat(childJsonName));
                }
            }
        } else if (elementObject instanceof JSONArray) {

            JSONArray jsonArray = (JSONArray) elementObject;

            for (Object child : jsonArray) {
                for (String childPath : getJsonElementPaths(child)) {
                    listOfLists.add(childPath);
                }
            }
        }

        if (listOfLists.size() == 0) {
            listOfLists.add("");
        }

        return listOfLists;
    }
}
