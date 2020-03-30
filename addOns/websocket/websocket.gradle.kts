import org.zaproxy.gradle.addon.AddOnStatus

version = "22"
description = "Allows you to inspect WebSocket communication."

zapAddOn {
    addOnName.set("WebSockets")
    addOnStatus.set(AddOnStatus.RELEASE)
    zapVersion.set("2.9.0")

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
                            semVer.set("2.*")
                        }
                    }
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
    compileOnly(parent!!.childProjects.get("fuzz")!!)

    testImplementation(project(":testutils"))
}
