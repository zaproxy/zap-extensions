description = "Inspect, attack gRPC endpoints, and decode protobuf messages."

zapAddOn {
    addOnName.set("gRPC Support")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/grpc-support/")
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
    testImplementation(project(":testutils"))
    implementation("io.grpc:grpc-protobuf:1.61.1")
}
