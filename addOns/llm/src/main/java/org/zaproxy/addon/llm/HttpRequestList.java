package org.zaproxy.addon.llm;

import dev.langchain4j.model.output.structured.Description;

import java.util.List;

public class HttpRequestList {

    @Description("List of HTTP request objects")
    private List<HttpRequest> requests;

    public HttpRequestList(List<HttpRequest> requests) {
        this.requests = requests;
    }

    public List<HttpRequest> getRequests() {
        return requests;
    }

    public void setRequests(List<HttpRequest> requests) {
        this.requests = requests;
    }


    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("HttpRequestList {\n");
        for (HttpRequest request : requests) {
            sb.append("  ").append(request).append(",\n");
        }
        sb.append("}");
        return sb.toString();
    }
}

