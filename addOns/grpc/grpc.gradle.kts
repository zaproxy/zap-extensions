description = "Inspect, attack gRPC endpoints, and decode protobuf messages."

zapAddOn {
    addOnName.set("gRPC Support")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/grpc-support/")
        extensions {
            register("org.zaproxy.zap.extension.grpc.internal.ExtensionGrpcWebSocket") {
                classnames {
                    allowed.set(listOf("org.zaproxy.zap.extension.grpc.internal"))
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
}
