package org.zaproxy.zap.extension.llmheader;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GeminiClient {

    private static final Logger LOGGER = LogManager.getLogger(GeminiClient.class);
    private static final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    public static List<LLMIssue> analyze(Map<String, String> headers, String bridgeUrl, String apiKey, String model) {
        System.out.println("DEBUG: GeminiClient.analyze called.");
        System.out.println("DEBUG: BridgeURL: " + bridgeUrl);
        System.out.println("DEBUG: API Key present: " + (apiKey != null && !apiKey.isEmpty()));

        if (bridgeUrl != null && !bridgeUrl.isEmpty()) {
            return analyzeLocalBridge(headers, bridgeUrl);
        } else if (apiKey != null && !apiKey.isEmpty()) {
            return analyzeDirectGemini(headers, apiKey, model);
        }
        System.out.println("DEBUG: No backend configured (neither bridge nor API key).");
        return Collections.emptyList();
    }

    private static List<LLMIssue> analyzeLocalBridge(Map<String, String> headers, String bridgeUrl) {
        try {
            System.out.println("DEBUG: Calling Local Bridge: " + bridgeUrl);
            JSONObject json = new JSONObject();
            json.put("headers", headers);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(bridgeUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json.toString()))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("DEBUG: Bridge Response Code: " + response.statusCode());
            System.out.println("DEBUG: Bridge Response Body: " + response.body());

            if (response.statusCode() == 200) {
                return LLMResultParser.parse(response.body());
            }
        } catch (Exception e) {
            System.out.println("DEBUG: Error calling local bridge: " + e.getMessage());
            e.printStackTrace();
            LOGGER.error("Error calling local bridge", e);
        }
        return Collections.emptyList();
    }

    private static List<LLMIssue> analyzeDirectGemini(Map<String, String> headers, String apiKey, String model) {
        try {
            // ... (rest of the method logic, just adding prints)
            // For brevity in replacement, re-implementing just the start to show where to
            // add logs.
            // But since I must replace blocks, I will replace the whole method or relevant
            // parts.
            System.out.println("DEBUG: Calling Direct Gemini API");

            JSONObject headersJson = new JSONObject();
            headersJson.put("headers", headers);
            String prompt = "You are a security expert. Analyze the following HTTP headers for security weaknesses. " +
                    "Check for missing security headers, misconfigurations, and information leakage.\n" +
                    "Return strictly a JSON array of objects. Do not include markdown formatting.\n" +
                    "Each object must have these fields:\n" +
                    "- \"issue\": Title of the security issue.\n" +
                    "- \"severity\": One of \"low\", \"medium\", \"high\".\n" +
                    "- \"confidence\": One of \"low\", \"medium\", \"high\".\n" +
                    "- \"recommendation\": A brief advice on how to fix it.\n\n" +
                    "Headers to analyze:\n" + headersJson.toString();

            JSONObject contentPart = new JSONObject();
            contentPart.put("text", prompt);

            JSONObject parts = new JSONObject();
            parts.put("parts", new JSONArray().element(contentPart));

            JSONObject requestBody = new JSONObject();
            requestBody.put("contents", new JSONArray().element(parts));

            // Force JSON response
            JSONObject generationConfig = new JSONObject();
            generationConfig.put("responseMimeType", "application/json");
            requestBody.put("generationConfig", generationConfig);

            // Use the model provided by the options, default to gemini-1.5-flash if empty
            String targetModel = (model != null && !model.isEmpty()) ? model : "gemini-1.5-flash";

            String endpoint = "https://generativelanguage.googleapis.com/v1beta/models/" +
                    targetModel +
                    ":generateContent?key=" + apiKey;

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(endpoint))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody.toString()))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            System.out.println("DEBUG: Gemini Response Code: " + response.statusCode());
            System.out.println("DEBUG: Gemini Response Body: " + response.body());

            if (response.statusCode() == 200) {
                JSONObject responseJson = JSONObject.fromObject(response.body());
                if (responseJson.has("candidates")) {
                    String text = responseJson.getJSONArray("candidates")
                            .getJSONObject(0)
                            .getJSONObject("content")
                            .getJSONArray("parts")
                            .getJSONObject(0)
                            .getString("text");
                    System.out.println("DEBUG: Parsed Text: " + text);
                    return LLMResultParser.parse(text);
                }
            } else {
                LOGGER.error("Gemini API error: " + response.statusCode() + " " + response.body());
            }
        } catch (Exception e) {
            System.out.println("DEBUG: Error calling Gemini API: " + e.getMessage());
            e.printStackTrace();
            LOGGER.error("Error calling Gemini API", e);
        }
        return Collections.emptyList();
    }
}
