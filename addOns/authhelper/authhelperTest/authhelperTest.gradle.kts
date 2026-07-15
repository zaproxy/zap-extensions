// Test add-on configured by convention, see Project.configureTestAddOn() in addOns.gradle.kts.
// Add anything else needed here, including overrides of the defaults.

// The mock LLM, which the rule set provided by this add-on is used with.
dependencies {
    zapAddOn(project(":addOns:llm:llmTest"))
}

zapAddOn {
    manifest {
        dependencies {
            addOns {
                register("llmTest") {
                    version.set(">=0.0.1")
                }
            }
        }
    }
}
