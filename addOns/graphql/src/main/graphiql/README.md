# GraphiQL IDE

## Gradle Task

The GraphiQL IDE that is packaged with the add-on is generated using the `generateGraphiQlHtmlPage` Gradle task that is
defined
in [`GenerateGraphiQlHtmlPage.java`](/buildSrc/src/main/java/org/zaproxy/gradle/tasks/GenerateGraphiQlHtmlPage.java)
available under the `buildSrc` directory at the root of this repository.

To quickly test your changes to GraphiQL locally, generate the page using

```shell
./gradlew aO:graphql:generateGraphiQlHtmlPage
```

and open the generated file (`build/resources/main/org/zaproxy/addon/graphql/resources/graphiql.html`) in your web
browser.

## Source Files

The React and GraphiQL CSS and JS files were taken from the following sources (at the time of writing):

| File                          | Location                                                       |
|-------------------------------|----------------------------------------------------------------|
| `graphiql.min.css`            | https://unpkg.com/graphiql/graphiql.min.css                    |
| `graphiql.min.js`             | https://unpkg.com/graphiql/graphiql.min.js                     |
| `react.production.min.js`     | https://unpkg.com/react-dom@18/umd/react-dom.min.js            |
| `react-dom.production.min.js` | https://unpkg.com/react-dom@18/umd/react-dom.production.min.js |

In order to upgrade these dependencies, it should be sufficient to replace these files with newer versions (ensure that
there are no breaking changes).

The other two source files, `zap.css` and `zap.js` contain custom code.
Any ZAP-specific GraphiQL plugins or tweaks should probably go in them.

## Licenses

| Resource                            | License                                                                          |
|-------------------------------------|----------------------------------------------------------------------------------|
| `graphiql.min.css`                  | [MIT License](https://github.com/graphql/graphiql/blob/graphiql%402.2.0/LICENSE) |
| `graphiql.min.js`                   | [MIT License](https://github.com/graphql/graphiql/blob/graphiql%402.2.0/LICENSE) |
| `react.production.min.js`           | [MIT License](https://github.com/facebook/react/blob/v18.2.0/LICENSE)            |
| `react-dom.production.min.js`       | [MIT License](https://github.com/facebook/react/blob/v18.2.0/LICENSE)            |
| SVG Icon for Schema Settings Button | [MIT License](https://github.com/tabler/tabler-icons/blob/v1.113.0/LICENSE)      |
