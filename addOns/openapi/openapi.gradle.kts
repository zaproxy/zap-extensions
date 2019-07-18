version = "14"
description = "Imports and spiders Open API definitions."

zapAddOn {
    addOnName.set("OpenAPI Support")
    zapVersion.set("2.8.0")

    manifest {
        author.set("ZAP Core Team plus Joanna Bona, Artur Grzesica, Markus Kiss, Michal Materniak and Marcin Spiewak")
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.openapi.OpenApiAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/openapi/resources/Messages.properties"))
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
    compileOnly("org.glassfish.jaxb:jaxb-runtime:2.3.2")
    implementation("io.swagger:swagger-parser:1.0.44")
    implementation("io.swagger:swagger-compat-spec-parser:1.0.44") {
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
