package org.zaproxy.zap.extension.foxhound.config;

import net.sf.json.JSONArray;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.foxhound.taint.NamedAndTagged;
import org.zaproxy.zap.extension.foxhound.taint.SinkTag;
import org.zaproxy.zap.extension.foxhound.taint.SourceTag;
import org.zaproxy.zap.extension.foxhound.taint.TaintSinkType;
import org.zaproxy.zap.extension.foxhound.taint.TaintSourceType;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class FoxhoundConstants {

    public static final String RESOURCE = "/org/zaproxy/zap/extension/foxhound/resources";
    private static final String SOURCE_AND_SINK_LIST = RESOURCE + "/sourcessinks.json";
    private static final Logger LOGGER = LogManager.getLogger(FoxhoundConstants.class);
    public static final String FOXHOUND_256 = RESOURCE + "/default256.png";
    public static final String FOXHOUND_16 = RESOURCE + "/default16.png";

    public static Set<TaintSourceType> ALL_SOURCES;
    public static Set<TaintSinkType> ALL_SINKS;

    public static List<String> ALL_SOURCE_NAMES;
    public static List<String> ALL_SINK_NAMES;

    public static Map<String, TaintSourceType> SOURCE_NAME_TYPE_MAP;
    public static Map<String, TaintSinkType> SINK_NAME_TYPE_MAP;

    static {
        try {
            loadSourceAndSinkConfig();
            // Cache source and sink names
            ALL_SOURCE_NAMES = ALL_SOURCES.stream().map(NamedAndTagged::getName).toList();
            ALL_SINK_NAMES = ALL_SINKS.stream().map(NamedAndTagged::getName).toList();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static void loadSourceAndSinkConfig() throws JSONException, IOException {
        LOGGER.info("Loading source and sink config from {}", SOURCE_AND_SINK_LIST);
        InputStream inputStream = FoxhoundConstants.class.getResourceAsStream(SOURCE_AND_SINK_LIST);
        InputStreamReader streamReader = new InputStreamReader(inputStream, StandardCharsets.UTF_8);
        BufferedReader bufferedReader = new BufferedReader(streamReader);

        StringBuilder sb = new StringBuilder();

        String inputStr;
        while ((inputStr = bufferedReader.readLine()) != null)
            sb.append(inputStr);

        JSONObject jsonObject = JSONObject.fromObject(sb.toString());

        // Sources
        ALL_SOURCES = new HashSet<>();
        SOURCE_NAME_TYPE_MAP = new HashMap<>();
        JSONArray sourceArray = jsonObject.getJSONArray("sources");
        for (int i = 0, size = sourceArray.size(); i < size; i++) {
            JSONObject sourceObject = sourceArray.getJSONObject(i);
            TaintSourceType source = new TaintSourceType(sourceObject.getString("name"));
            JSONArray tags = sourceObject.getJSONArray("tags");
            for (int j = 0, l = tags.size(); j < l; j++) {
                String tagString = tags.getString(j);
                SourceTag sourceTag = NamedAndTagged.getTagForString(tags.getString(j), SourceTag.class);
                if (sourceTag != null) {
                    source.getTags().add(sourceTag);
                }
            }
            ALL_SOURCES.add(source);
            SOURCE_NAME_TYPE_MAP.put(sourceObject.getString("name"), source);
        }

        // Sinks
        ALL_SINKS = new HashSet<>();
        SINK_NAME_TYPE_MAP = new HashMap<>();
        JSONArray sinkArray = jsonObject.getJSONArray("sinks");
        for (int i = 0, size = sinkArray.size(); i < size; i++) {
            JSONObject sinkObject = sinkArray.getJSONObject(i);
            TaintSinkType sink = new TaintSinkType(sinkObject.getString("name"));
            JSONArray tags = sinkObject.getJSONArray("tags");
            for (int j = 0, l = tags.size(); j < l; j++) {
                String tagString = tags.getString(j);
                SinkTag sinkTag = NamedAndTagged.getTagForString(tags.getString(j), SinkTag.class);
                if (sinkTag != null) {
                    sink.getTags().add(sinkTag);
                }
            }
            ALL_SINKS.add(sink);
            SINK_NAME_TYPE_MAP.put(sinkObject.getString("name"), sink);
        }
    }

    public static Set<TaintSourceType> getSourceTypesWithTag(SourceTag tag) {
        return ALL_SOURCES.stream().filter(e -> e.getTags().contains(tag)).collect(Collectors.toSet());
    }

    public static Set<TaintSinkType> getSinkTypesWithTag(SinkTag tag) {
        return ALL_SINKS.stream().filter(e -> e.getTags().contains(tag)).collect(Collectors.toSet());
    }

    public static Set<String> getSourceNamesWithTag(SourceTag tag) {
        return getSourceTypesWithTag(tag).stream().map(NamedAndTagged::getName).collect(Collectors.toSet());
    }

    public static Set<String> getSinkNamesWithTag(SinkTag tag) {
        return getSinkTypesWithTag(tag).stream().map(NamedAndTagged::getName).collect(Collectors.toSet());
    }

    public static Set<TaintSourceType> getSourceTypesWithTags(Collection<SourceTag> tags) {
        return ALL_SOURCES.stream().filter(e -> !Collections.disjoint(tags, e.getTags())).collect(Collectors.toSet());
    }

    public static Set<TaintSinkType> getSinkTypesWithTags(Collection<SinkTag> tags) {
        return ALL_SINKS.stream().filter(e -> !Collections.disjoint(tags, e.getTags())).collect(Collectors.toSet());
    }

    public static Set<String> getSourceNamesWithTags(Collection<SourceTag> tags) {
        return getSourceTypesWithTags(tags).stream().map(NamedAndTagged::getName).collect(Collectors.toSet());
    }

    public static Set<String> getSinkNamesWithTags(Collection<SinkTag> tags) {
        return getSinkTypesWithTags(tags).stream().map(NamedAndTagged::getName).collect(Collectors.toSet());
    }

}
