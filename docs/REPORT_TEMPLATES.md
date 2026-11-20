# Email report templates

VEILUX writes escalation emails from a case. The AI writes the content; your
template decides how the email looks, which severity scale it uses, what the
subject says and which language the AI writes in. Templates are stored in your
browser and never leave it, except in Settings backups you export yourself.

## Using reports

1. In the popup, open a case and click **Report** (bottom bar).
2. Choose a template, and optionally set the alert title, case or ticket ID,
   severity and the template's own fields. Empty title: the AI writes one.
   Severity on *Auto*: the AI picks a level from the template's scale. Empty
   case ID: the template's placeholder (for example `[Case ID]`) is used.
3. Add **Instructions for this email** if you want to say who to address, the
   tone, or what to leave out. Facts about the case belong in **Case notes**
   (your own text and answers kept from Ask), which the report always
   receives; it states them as findings of the case, never as questions and
   answers. The **Uses:** line under the button lists what the report gets.
4. **Generate report.** No analysis is needed first. The AI receives the whole
   case: logs, statistics, case notes, threat-intelligence results, the
   case's AI analysis when there is one, and your instructions for the email. Threat
   intelligence and the earlier analysis inform the report but are not copied
   into it, and no new threat-intelligence lookups run for a report. Everything goes
   through the same protection as an analysis, including the credential
   review, before the AI sees it.
5. Check the preview, then **Copy for email** and paste into a new message, and
   **Copy subject**. Copy for email takes only the body of the email: the
   subject and the page around it are left out. **Edit content** changes the text without a new AI request.
   **Open in a new tab** shows the full email.

Real values (users, hosts, addresses) are restored in the finished email on
your computer only; credentials stay hidden. A template can keep every value
masked instead. The report never replaces the case's analysis.

## Creating a template

Settings → **Email reports** → **New template** (or **Copy to customize** on the
built-in template), then:

| Setting | What it does |
| --- | --- |
| Template name | Shown in the popup's template list |
| Language of the report | The language the AI writes in |
| Severity scale | Your company's or tools' levels, lowest to highest, each with a colour |
| Subject pattern | The email subject, for example `Case #{{case_id}} - {{title}} ({{team}})` |
| Text when no case ID is entered | Placeholder used when the case ID field is empty |
| Instructions for the AI | Tone and focus. VEILUX adds the answer format, language and scale itself |
| Email HTML | The email, with placeholders (below) |
| Keep protected values masked | Leave markers such as `⟦USER#1⟧` instead of real values |

**Preview with sample data** shows the template filled with an example report.
Choose the default template at the top of the section. **Export** saves a
template as a `.json` file to share with your team; **Import template file**
adds one.

## Template placeholders

Every value is HTML-escaped, so log content can never add markup. Line breaks
become `<br>`.

| Placeholder | Value |
| --- | --- |
| `{{title}}` | Alert title |
| `{{case_id}}` | Case or ticket ID, or the placeholder text |
| `{{severity}}`, `{{severity_color}}` | Severity level and its colour (for `style="color:{{severity_color}}"`) |
| `{{detection_time}}` | Detection date and time from the logs, or `unknown`. Epoch numbers become readable UTC dates |
| `{{date}}` | Today's date |
| `{{summary}}`, `{{context}}` | Summary and technical context |
| `{{subject}}` | The filled subject line |
| `{{name}}` | Any other name becomes a field on the report page, such as `{{team}}` |
| `{{ai_name}}` | A value the AI writes, such as `{{ai_affected_asset}}` or `{{ai_business_impact}}` |
| `{{name\|upper}}`, `{{name\|lower}}` | The value in capitals or lower case, for example `{{team\|upper}}` |

Lists repeat the block between `{{#name}}` and `{{/name}}`:

```html
{{#details}}<tr><td>{{label}}</td><td {{#highlight}}style="background:#FFF7ED"{{/highlight}}>{{value}}</td></tr>{{/details}}
<ul>{{#risks}}<li>{{.}}</li>{{/risks}}</ul>
<ol>{{#recommendations}}<li>{{.}}</li>{{/recommendations}}</ol>
{{#annexes}}<p>{{label}}: [insert screenshot]</p>{{/annexes}}
{{#extra_sections}}<h3>{{title}}</h3><p>{{content}}</p>{{/extra_sections}}
```

To show a section once when its list has items, use `{{#has_details}}`,
`{{#has_risks}}`, `{{#has_recommendations}}`, `{{#has_annexes}}` or
`{{#has_extra_sections}}`.

## Fixed placeholders and AI freedom

A template mixes both:

- **Exact values.** Each `{{ai_…}}` placeholder gets exactly one short value
  from the AI, and the analyst's fields (`{{team}}`, case ID, title,
  severity) are never rewritten by it.
- **Free content.** `details` is a table of as many rows as the case needs,
  with labels the AI chooses (user, host, process, rule, count…).
  `extra_sections` holds anything relevant that fits nowhere else, each with
  its own title. Keep a `{{#details}}` row and an `{{#extra_sections}}` block
  in your template so this content has a place to go.
`{{^name}}…{{/name}}` shows its content when a value is empty.

## Converting an existing company template

1. Open your current email's HTML and paste it into **Email HTML** (or use
   **Import an HTML file**).
2. Replace the example values with placeholders: the title with `{{title}}`,
   the summary with `{{summary}}`, and so on.
3. Wrap one repeated table row in `{{#details}}…{{/details}}`, and one list
   item in `{{#risks}}…{{/risks}}` and `{{#recommendations}}…{{/recommendations}}`.
4. Add `{{#extra_sections}}…{{/extra_sections}}` where free sections should go.
5. Enter your subject format and severity scale, then **Preview with sample data**.

Keep styles inline (`style="…"`): many mail clients drop `<style>` blocks.
