package org.zaproxy.zap.extension.foxhound.taint;

import net.sf.json.JSONArray;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;

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
        taint.setLocation(detailObject.getString("loc"));
        taint.setParentLocation(detailObject.getString("parentloc"));
        taint.setReferrer(detailObject.getString("referrer"));
        taint.setSinkName(detailObject.getString("sink"));
        taint.setTimeStamp(detailObject.getLong("timestamp"));
        taint.setSubframe(detailObject.getBoolean("subframe"));

        JSONArray taintArray = jsonObject.getJSONArray("taint");
        for (int i = 0, size = taintArray.size(); i < size; i++)
        {
            TaintRange range = new TaintRange();
            JSONObject nodeObject = taintArray.getJSONObject(i);

            range.setBegin(nodeObject.getInt("begin"));
            range.setEnd(nodeObject.getInt("end"));

            range.setStr(taint.getStr().substring(range.getBegin(), range.getEnd()));

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
                location.setScriptLine(locationObject.getInt("scriptline"));
                location.setMd5(locationObject.getString("scripthash"));
                operation.setLocation(location);

                // The taint reporting adds a "ReportTaintSink" operation at the end, which we can ignore
                if (!operation.getArguments().isEmpty() && operation.getArguments().get(0).equals("ReportTaintSink")) {
                    continue;
                }

                // If we are adding the first operation, it must be the sink
                if (range.getSink() == null) {
                    range.setSink(operation);
                }

                if (operation.isSource()) {
                    range.getSources().add(operation);
                }

                // The Taint flow from Foxhound starts with the sink and works backwards, so reverse direction
                range.getFlow().addFirst(operation);
            }
            // Add the range
            taint.getTaintRanges().add(range);
            // Combine all sources from each flow
            taint.getSources().addAll(range.getSources());
            // The sinks should all be the same, only add the first
            if ((taint.getSink() == null) && (range.getSink() != null)){
                taint.setSink(range.getSink());
            }
        }

        return taint;
    }

}
