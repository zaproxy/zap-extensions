description = "Inspect, attack gRPC endpoints, and decode protobuf messages."

zapAddOn {
    addOnName.set("gRPC Support")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/grpc-support/")
        extensions {
            register("org.zaproxy.addon.grpc.internal.websocket.ExtensionGrpcWebSocket") {
                classnames {
                    allowed.set(listOf("org.zaproxy.addon.grpc.internal.websocket"))
                }
                dependencies {
                    addOns {
                        register("websocket")
                    }
                }
            }
        }
    }
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}

dependencies {
    zapAddOn("websocket")
    testImplementation(project(":testutils"))
    implementation("io.grpc:grpc-protobuf:1.61.1")

    testImplementation(libs.log4j.core)
}
