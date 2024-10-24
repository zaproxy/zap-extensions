package org.zaproxy.addon.llm;

import dev.langchain4j.model.output.structured.Description;

public class Confidence {

    @Description("The level of confidence, typically represented as a percentage or a descriptive term")
    private Integer level;

    @Description("A textual justification for the assigned confidence level")
    private String explanation;

    // Constructor
    public Confidence(Integer level, String justification) {
        this.level = level;
        this.explanation = justification;
    }

    // Getter for level
    public Integer getLevel() {
        return level;
    }

    // Setter for level
    public void setLevel(Integer level) {
        this.level = level;
    }

    // Getter for explanation
    public String getExplanation() {
        return explanation;
    }

    // Setter for explanation
    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }

    @Override
    public String toString() {
        return "Confidence {\n"
                + "level=" + level + "\n"
                + ", explanation='" + explanation + "\n"
                + "}";
    }
}

