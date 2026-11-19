# Zest test add-on

Test apps and integration tests for the Zest add-on. The build configures it from its location
(`addOns/zest/zestTest`), see the Dev add-on help for how test add-ons work.

## Shadow DOM

`http://localhost:9091/zest/shadow-dom/` lists the cases, each in its own directory. Each page has the link `#link`,
the button `#button` and the form `#form` (input `#input`, button `#submit`) in the innermost shadow root, the hosts
are `#host0`, `#host1`, ... (outermost first). Acting on them requests `link`, `button` and `form?value=<input>`
in the directory of the case, which reply with `<case> <action> OK`.

| Case                  | Shadow roots    | Delay                 |
|-----------------------|-----------------|-----------------------|
| `open`                | open            | -                     |
| `closed`              | closed          | -                     |
| `open-open`           | open > open     | -                     |
| `closed-closed`       | closed > closed | -                     |
| `open-closed`         | open > closed   | -                     |
| `closed-open`         | closed > open   | -                     |
| `delayed-open`        | open            | 2s                    |
| `delayed-closed`      | closed          | 2s                    |
| `delayed-open-closed` | open > closed   | 2s before each root   |
| `delayed-closed-open` | closed > open   | 2s before each root   |

The cases are defined in `ShadowDomCase`, both the page and the script in `addOnData/dev/server/zest/shadow-dom/`.

## Integration tests

`src/main/zapHomeFiles/integration-tests/zest/plans/shadow-dom-<case>.yaml` are Automation Framework plans which are
installed with this add-on to `integration-tests/zest/plans` in the ZAP home. Each has a standalone Zest script inline,
which uses the shadow path of the client elements to click the link, click the button, and fill and submit the form
(waiting for the elements, for the delayed cases). The `url` tests then check that each target was requested from the page.
They need Firefox, for example:

    zap.sh -dev -cmd -autorun <ZAP home>/integration-tests/zest/plans/shadow-dom-closed-open.yaml
