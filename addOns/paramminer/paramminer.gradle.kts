description = "Identify hidden, unlinked parameters. Useful for finding web cache poisoning vulnerabilities."

zapAddOn {
    addOnName.set("Parameter Miner")
    zapVersion.set("2.11.1")

    manifest {
        author.set("ZAP Dev Team and Arkaprabha Chakraborty")
    }
}

dependencies {
    testImplementation(project(":testutils"))
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}
