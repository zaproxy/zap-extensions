description = "An add-on that implements an MCP server in ZAP."

zapAddOn {
    addOnName.set("MCP Server")

    manifest {
        author.set("ZAP Dev Team")
        extensions {
            register("org.zaproxy.addon.mcp.ExtensionMcp")
        }
        dependencies {
            addOns {
                register("automation") {
                    version.set(">=0.31.0")
                }
                register("commonlib") {
                    version.set(">=1.17.0")
                }
                register("network") {
                    version.set(">=0.1.0")
                }
            }
        }
    }
}

dependencies {
    zapAddOn("automation")
    zapAddOn("commonlib")
    zapAddOn("network")

    testImplementation(project(":testutils"))
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}
