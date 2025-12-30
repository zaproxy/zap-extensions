package org.zaproxy.zap.extension.llmheader;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class LLMRequestManager {

    private static LLMRequestManager instance;
    private final Map<Map<String, String>, List<LLMIssue>> cache;
    private final AtomicInteger requestCount;
    private final ScheduledExecutorService scheduler;

    private LLMRequestManager() {
        this.cache = new ConcurrentHashMap<>();
        this.requestCount = new AtomicInteger(0);
        this.scheduler = Executors.newScheduledThreadPool(1);
        this.scheduler.scheduleAtFixedRate(() -> requestCount.set(0), 1, 1, TimeUnit.MINUTES);
    }
    public static synchronized LLMRequestManager getInstance() {
        if (instance == null) {
            instance = new LLMRequestManager();
        }
        return instance;
    }

    public List<LLMIssue> getCachedResult(Map<String, String> headers) {
        if (headers == null) {
            return null;
        }
        return cache.get(headers);
    }

    public void cacheResult(Map<String, String> headers, List<LLMIssue> issues) {
        if (headers != null && issues != null) {
            cache.put(headers, issues);
        }
    }

    public boolean allowRequest(int maxRequestsPerMinute) {
        return requestCount.get() < maxRequestsPerMinute;
    }

    public void incrementRequestCount() {
        requestCount.incrementAndGet();
    }
    
    public synchronized void shutdown() {
        scheduler.shutdown();
        instance = null;
    }
}
