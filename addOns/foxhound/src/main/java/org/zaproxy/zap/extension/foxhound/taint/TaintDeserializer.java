/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.foxhound.taint;

import net.sf.json.JSONArray;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.foxhound.utils.StringUtils;

public class TaintDeserializer {
    private static final Logger LOGGER = LogManager.getLogger(TaintDeserializer.class);

    public static String url(String jsonString) {
        JSONObject jsonObject;
        String url = "";
        try {
            jsonObject = JSONObject.fromObject(jsonString);
            JSONObject detailObject = jsonObject.getJSONObject("detail");
            url = detailObject.getString("loc");

            LOGGER.debug("Extracted URL: " + url);

        } catch (JSONException e) {
            LOGGER.warn("Unable to parse as JSON: {}", jsonString, e);
        }
        return url;
    }

    public static TaintInfo deserializeTaintInfo(String jsonString) throws JSONException {
        TaintInfo taint = new TaintInfo();
        JSONObject jsonObject = JSONObject.fromObject(jsonString);

        JSONObject detailObject = jsonObject.getJSONObject("detail");

        taint.setStr(detailObject.getString("str"));
        taint.setLocationName(detailObject.getString("loc"));
        taint.setParentLocation(detailObject.getString("parentloc"));
        taint.setReferrer(detailObject.getString("referrer"));
        taint.setSinkName(detailObject.getString("sink"));
        taint.setTimeStamp(detailObject.getLong("timestamp"));
        taint.setSubframe(detailObject.getBoolean("subframe"));

        JSONArray taintArray = jsonObject.getJSONArray("taint");
        for (int i = 0, size = taintArray.size(); i < size; i++) {
            TaintRange range = new TaintRange();
            JSONObject nodeObject = taintArray.getJSONObject(i);

            range.setBegin(nodeObject.getInt("begin"));
            range.setEnd(nodeObject.getInt("end"));

            try {
                range.setStr(
                        StringUtils.limitedSubstring(
                                taint.getStr(), range.getBegin(), range.getEnd()));
            } catch (StringIndexOutOfBoundsException e) {
                LOGGER.warn(e.toString());
            }
            JSONArray flowArray = nodeObject.getJSONArray("flow");
            // The taint flow navigates backwards from the sink, so reverse here
            for (int j = 0, l = flowArray.size(); j < l; j++) {
                TaintOperation operation = new TaintOperation();
                JSONObject operationObject = flowArray.getJSONObject(j);

                operation.setOperation(operationObject.getString("operation"));
                operation.setSource(operationObject.getBoolean("source"));

                // Arguments
                JSONArray argArray = operationObject.getJSONArray("arguments");
                for (int k = 0, m = argArray.size(); k < m; k++) {
                    operation.getArguments().add(argArray.getString(k));
                }

                // Set Location
                JSONObject locationObject = operationObject.getJSONObject("location");
                TaintLocation location = new TaintLocation();
                location.setFilename(locationObject.getString("filename"));
                location.setFunction(locationObject.getString("function"));
                location.setLine(locationObject.getInt("line"));
                location.setPos(locationObject.getInt("pos"));
                if (locationObject.has("next_line")) {
                    location.setNextLine(locationObject.getInt("next_line"));
                }
                if (locationObject.has("next_pos")) {
                    location.setNextPos(locationObject.getInt("next_pos"));
                }
                location.setScriptLine(locationObject.getInt("scriptline"));
                location.setMd5(locationObject.getString("scripthash"));
                operation.setLocation(location);

                // The taint reporting adds a "ReportTaintSink" operation at the end, which we can
                // ignore
                if (!operation.getArguments().isEmpty()
                        && operation.getArguments().get(0).equals("ReportTaintSink")) {
                    continue;
                }

                // If we are adding the first operation, it must be the sink
                if (range.getSink() == null) {
                    range.setSink(operation);
                }

                if (operation.isSource()) {
                    range.getSources().add(operation);
                }

                // The Taint flow from Foxhound starts with the sink and works backwards, so reverse
                // direction
                range.getFlow().add(0, operation);
            }
            // Add the range
            taint.getTaintRanges().add(range);
            // Combine all sources from each flow
            taint.getSources().addAll(range.getSources());
            // The sinks should all be the same, only add the first
            if ((taint.getSink() == null) && (range.getSink() != null)) {
                taint.setSink(range.getSink());
            }
        }

        if (taint != null) {
            LOGGER.debug("Deserialized flow: {}", taint);
        }

        return taint;
    }
}
