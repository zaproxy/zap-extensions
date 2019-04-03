version = "13"
description = "Imports and spiders Open API definitions."

zapAddOn {
    addOnName.set("OpenAPI Support")
    zapVersion.set("2.6.0")

    manifest {
        author.set("ZAP Core Team plus Joanna Bona, Artur Grzesica, Michal Materniak and Marcin Spiewak")
    }
}

configurations {
    "implementation" {
        // Not needed:
        exclude(group = "com.google.code.findbugs", module = "jsr305")
        exclude(group = "org.slf4j", module = "slf4j-ext")
    }
}

dependencies {
    implementation("io.swagger:swagger-parser:1.0.33")
    implementation("io.swagger:swagger-compat-spec-parser:1.0.33") {
        // Not needed:
        exclude(group = "com.github.java-json-tools", module = "json-schema-validator")
        exclude(group = "org.apache.httpcomponents", module = "httpclient")
    }
    implementation("org.slf4j:slf4j-log4j12:1.7.6") {
        // Provided by ZAP.
        exclude(group = "log4j")
    }

    testImplementation(project(":testutils"))
}
