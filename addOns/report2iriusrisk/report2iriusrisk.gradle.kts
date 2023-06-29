version = "0.0.2"
description = "Report to IriusRisk."

zapAddOn {
    addOnName.set("Report To IriusRisk")
    zapVersion.set("2.10.0")

    manifest {
        author.set("Álvaro Vázquez Ortiz")
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
    implementation(files("lib/zap-clientapi-1.11.0.jar"))
    implementation("org.apache.httpcomponents:httpclient:4.5.13")
    implementation("org.apache.httpcomponents:httpmime:4.5.14")
}