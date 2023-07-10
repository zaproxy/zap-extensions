import org.zaproxy.gradle.addon.AddOnStatus

description = "This Value Generator Add-on allows a user to define field names and values to be used when submitting values to an app. Fields can be added, modified, enabled/disabled, and deleted."

zapAddOn {
    addOnName.set("Value Generator")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/value-generator/")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}
