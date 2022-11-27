/**
 * This script is responsible for rendering the GraphiQL dashboard.
 * It also adds custom elements for convenience of usage with ZAP.
 */
const e = React.createElement
const root = ReactDOM.createRoot(document.getElementById('graphiql'))
const createGraphiQlBody = () => e(GraphiQL, {
        plugins: [schemaSettings],
        fetcher: GraphiQL.createFetcher({
            url: localStorage.getItem('graphiql:endpointUrl') || '',
        }),
        defaultEditorToolsVisibility: true,
    },
    e(GraphiQL.Logo, null, e('div', {className: 'graphiql-logo'},
        e('a', {
            className: 'graphiql-logo-link',
            href: 'https://www.zaproxy.org/',
            target: '_blank',
            rel: 'noreferrer'
        }, 'ZAP'),
        ' x ',
        e('a', {
            className: 'graphiql-logo-link',
            href: 'https://github.com/graphql/graphiql',
            target: '_blank',
            rel: 'noreferrer'
        }, 'Graph', e('em', null, 'i'), 'QL'))),
)

const schemaSettings = {
    title: 'Schema Settings',
    content: () => {
        return (
            e('div', null,
                e('div', {className: 'graphiql-schema-settings-header'},
                    e('div', {className: 'graphiql-schema-settings-header-content'},
                        e('div', {className: 'graphiql-schema-settings-title'}, 'Schema')
                    )
                ),
                e('h3', null, 'Endpoint URL'),
                e('form', {
                        onSubmit: evt => {
                            evt.preventDefault()
                            localStorage.setItem('graphiql:endpointUrl', evt.target['endpoint-url'].value)
                            root.render(createGraphiQlBody())
                        }
                    },
                    e('div', {className: 'graphiql-schema-settings-endpoint-input'},
                        e('input', {
                            id: 'endpoint-url',
                            type: 'text',
                            'aria-autocomplete': 'both',
                            'aria-controls': 'listbox--97',
                            'aria-expanded': 'false',
                            'aria-haspopup': 'listbox',
                            'aria-label': 'Endpoint URL',
                            'placeholder': 'https://example.com/graphql',
                            'data-reach-combobox-input': '',
                            'data-state': 'idle',
                            defaultValue: localStorage.getItem('graphiql:endpointUrl') || ''
                        }, null),
                        e('input', {
                            type: 'submit',
                            value: 'Save',
                            className: 'graphiql-schema-settings-endpoint-submit'
                        }, null),
                    )
                )
            )
        )
    },
    icon: () => {
        return e('svg', {
                xmlns: 'http://www.w3.org/2000/svg',
                height: '1em',
                viewBox: '2 2 20 20',
                strokeWidth: '1.5',
                stroke: 'currentColor',
                fill: 'none',
                strokeLinecap: 'square',
                strokeLinejoin: 'round'
            }, e('path', {stroke: 'none', d: 'M0 0h24v24H0z', fill: 'none'}), e('circle', {
                cx: '12',
                cy: '14',
                r: '2'
            }), e('path', {d: 'M12 10.5v1.5'}),
            e('path', {d: 'M12 16v1.5'}),
            e('path', {d: 'M15.031 12.25l-1.299 .75'}),
            e('path', {d: 'M10.268 15l-1.3 .75'}),
            e('path', {d: 'M15 15.803l-1.285 -.773'}),
            e('path', {d: 'M10.285 12.97l-1.285 -.773'}),
            e('path', {d: 'M14 3v4a1 1 0 0 0 1 1h4'}),
            e('path', {d: 'M17 21h-10a2 2 0 0 1 -2 -2v-14a2 2 0 0 1 2 -2h7l5 5v11a2 2 0 0 1 -2 2z'})
        )
    }
}
root.render(createGraphiQlBody())