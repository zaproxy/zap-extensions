description = "An add-on providing additional insights into what ZAP finds."

zapAddOn {
    addOnName.set("Insights")

    manifest {
        author.set("ZAP Dev Team")
    }
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}
