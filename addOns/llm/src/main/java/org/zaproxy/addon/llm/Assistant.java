package org.zaproxy.addon.llm;

import dev.langchain4j.service.SystemMessage;
import dev.langchain4j.service.UserMessage;

import dev.langchain4j.service.V;
import org.zaproxy.addon.llm.HttpRequestList;
import org.zaproxy.addon.llm.Confidence;

public interface Assistant {
    @UserMessage("Given the following swagger generate list of chained HTTP request to simulate a real world user : {{swagger}} ")
    org.zaproxy.addon.llm.HttpRequestList extractHttpRequests(String swagger);

    @SystemMessage("You are a web application security expert in review false positives. Answer only in JSON.")
    @UserMessage("Your task is to review the following finding from ZAP (Zed Attack Proxy).\n"
            + "The confidence level is a pull down field which allows you to specify how confident you are in the validity of the finding : \n"
            + "- 0 if it's False Positive\n"
            + "- 1 if it's Low\n"
            + "- 2 if it's Medium\n"
            + "- 3 if it's High\n"
            + "- 4 if it's Confirmed\n"
            + "\n"
            + "The alert is described as follow : {{description}}\n"
            + "\n"
            + "As evidence, the HTTP response contains :\n"
            + "---\n"
            + "{{evidence}}\n"
            + "---\n"
            + "Provide short consistent explanation of the new score.\n")

    Confidence review(@V("description") String description, @V("evidence") String evidence);
}