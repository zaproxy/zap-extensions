import org.zaproxy.gradle.addon.AddOnStatus

description = "Allows Kotlin to be used for ZAP scripting"

zapAddOn {
    addOnName.set("Kotlin Support")
    addOnStatus.set(AddOnStatus.ALPHA)

    manifest {
        author.set("StackHawk Engineering")
        url.set("https://www.zaproxy.org/docs/desktop/addons/kotlin-support/")
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
    api(libs.kotlin.stdlibJdk8)
    implementation(libs.kotlin.scripting)
    implementation(libs.kotlin.compiler)

    testImplementation(project(":testutils"))
    testRuntimeOnly(project(":addOns:encoder"))
}
