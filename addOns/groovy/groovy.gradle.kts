import org.zaproxy.gradle.addon.AddOnStatus

description = "Adds Groovy support to ZAP"

zapAddOn {
    addOnName.set("Groovy Support")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/groovy-support/")
    }
}

dependencies {
    implementation("org.codehaus.groovy:groovy-all:3.0.14")

    testImplementation(project(":testutils"))
    testImplementation(parent!!.childProjects.get("websocket")!!)
}
