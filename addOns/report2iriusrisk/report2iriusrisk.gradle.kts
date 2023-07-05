version = "0.1.0"
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
    implementation("org.apache.httpcomponents:httpclient:4.5.13")
    implementation("org.apache.httpcomponents:httpmime:4.5.14")
    implementation("com.google.code.gson:gson:2.8.9")

}