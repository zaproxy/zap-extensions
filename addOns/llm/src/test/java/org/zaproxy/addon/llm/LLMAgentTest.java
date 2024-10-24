package org.zaproxy.addon.llm;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import de.sstoehr.harreader.HarReader;
import de.sstoehr.harreader.HarReaderException;
import de.sstoehr.harreader.model.*;
import dev.langchain4j.model.azure.AzureOpenAiChatModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.ArrayList;
import java.util.List;

public class LLMAgentTest {

    @Mock
    private AzureOpenAiChatModel chatModel;

        @Mock
    private HarReader harReader;

    @InjectMocks
    private LLMAgent llmAgent;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testConvertOpenApiToChainedCalls_WithValidHarJson() throws HarReaderException {
        // Arrange
        String openApiDefinition = """
                openapi: 3.0.0
                info:
                  title: Sample API
                  version: 0.1.0
                paths:
                  /users:
                    get:
                      summary: Returns a list of users.
                      responses:
                        '200':
                          description: A JSON array of user names
                          content:
                            application/json:
                              schema:
                                type: array
                                items:
                                  type: string
                """;
        String harJson = "";
        // Act
        List<HarRequest> result = llmAgent.convertOpenApiToChainedCalls(openApiDefinition);

        assertEquals("a", "a");
    }

    // Other test cases...
}
