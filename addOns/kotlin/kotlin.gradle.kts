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
    val ktVersion = "1.3.72"
    api("org.jetbrains.kotlin:kotlin-stdlib-jdk8:$ktVersion")
    implementation("org.jetbrains.kotlin:kotlin-scripting-jsr223-embeddable:$ktVersion")
    implementation("org.jetbrains.kotlin:kotlin-compiler-embeddable:$ktVersion")

    testImplementation(project(":testutils"))
    testRuntimeOnly(project(":addOns:encoder"))
}
