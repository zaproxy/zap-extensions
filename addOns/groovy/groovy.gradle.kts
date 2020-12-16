import org.zaproxy.gradle.addon.AddOnStatus

version = "3.1.0"
description = "Adds Groovy support to ZAP"

zapAddOn {
    addOnName.set("Groovy Support")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/groovy-support/")
        notBeforeVersion.set("2.10.0")
    }
}

dependencies {
    implementation("org.codehaus.groovy:groovy-all:3.0.2")

    testImplementation(project(":testutils"))
    testImplementation(parent!!.childProjects.get("websocket")!!)
}
