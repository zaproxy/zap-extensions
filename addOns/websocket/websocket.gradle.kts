import org.zaproxy.gradle.addon.AddOnStatus

description = "Allows you to inspect WebSocket communication."

zapAddOn {
    addOnName.set("WebSockets")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/websockets/")
        classnames {
            restricted.set(listOf("org.zaproxy.zap.extension.websocket.fuzz"))
        }
        extensions {
            register("org.zaproxy.zap.extension.websocket.fuzz.ExtensionWebSocketFuzzer") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.websocket.fuzz"))
                }
                dependencies {
                    addOns {
                        register("fuzz") {
                            version.set("2.* | 13.*")
                        }
                    }
                }
            }

            register("org.zaproxy.zap.extension.websocket.manualsend.ExtensionWebSocketManualSend") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.websocket.manualsend"))
                }
                dependencies {
                    addOns {
                        register("requester") {
                            version.set("7.*")
                        }
                    }
                }
            }
        }
        dependencies {
            addOns {
                register("commonlib") {
                    version.set(">=1.23.0")
                }
            }
        }
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.websocket.WebSocketAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/websocket/resources/Messages.properties"))
    }
}

dependencies {
    zapAddOn("commonlib")
    zapAddOn("fuzz")
    zapAddOn("requester")

    testImplementation(project(":testutils"))
}
