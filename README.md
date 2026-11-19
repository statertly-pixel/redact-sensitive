# redact-sensitive

Redact emails, phone numbers, API keys, credit cards and other sensitive data from text and logs — before they leave your app.

Zero dependencies. Works in Node.js 16+ and in browsers via bundlers. TypeScript types included.

```js
const { redact } = require('redact-sensitive');

redact('Contact me at ana@example.com or 555-123-4567');
// 'Contact me at [EMAIL] or [PHONE]'

redact('Card 4111 1111 1111 1111, key sk-abcdefghij1234567890abcd');
// 'Card [CARD], key [API_KEY]'
```

## Why

Logs, error reports and support tickets routinely leak the very data they were meant to debug. One `console.log(user)` can put an email, a token or a card number into a log store, a crash report or a shared screenshot. `redact-sensitive` is a one-line safety net: run untrusted text through it before logging, storing or sending it anywhere.

## Install

```bash
npm install redact-sensitive
```

## Usage

### `redact(text, options?)`

```js
const { redact, redactObject, findSensitive } = require('redact-sensitive');

redact('Email ana@example.com, IP 203.0.113.42');
// 'Email [EMAIL], IP [IP]'

// Redact only emails
redact('a@b.com 555-123-4567', { only: ['email'] });
// '[EMAIL] 555-123-4567'

// Use one replacement for everything
redact('a@b.com', { keepLabels: false, replacement: '***' });
// '***'

// Override the label of one pattern type only
redact('a@b.com 555-123-4567', { labels: { email: '[E-MAIL]', phone: '[TEL]' } });
// '[E-MAIL] [TEL]'
// `keepLabels: false` still wins over per-type labels. Labels are keyed by
// pattern name (`email`, `phone`, `urlQuerySecret`, `authHeader`, ...).
// They also apply to values redacted because of their object key name,
// matched by the key name: redactObject({ password: 'x' }, { labels: { password: '[PWD]' } })

// Add your own pattern
redact('order #12345', {
  custom: [{ pattern: '#\\d+', replacement: '[ORDER]' }],
});
```

### `redactObject(value, options?)`

Recursively redacts strings inside objects and arrays. Useful for sanitising a whole log payload:

```js
redactObject({ user: { email: 'ana@example.com' }, tags: ['x@y.com'] });
// { user: { email: '[EMAIL]' }, tags: ['[EMAIL]'] }

// Arrays of log records are walked too, including nested arrays:
redactObject({ records: [
  { email: 'ana@example.com', token: '<token-1>' },
  { email: 'bob@example.com', token: '<token-2>' },
] });
// { records: [
//   { email: '[EMAIL]', token: '[TOKEN]' },
//   { email: '[EMAIL]', token: '[TOKEN]' },
// ] }

// Values stored under a sensitive key name are replaced outright,
// whatever their type — even when they look like plain text:
redactObject({ password: 'hunter2', apiKey: 'abc123secret', user: 'ana' });
// { password: '[PASSWORD]', apiKey: '[API_KEY]', user: 'ana' }

// Add your own sensitive key names with `sensitiveKeys`:
redactObject({ myPhrase: 'shh' }, { sensitiveKeys: ['myPhrase'] });
// { myPhrase: '[REDACTED]' }
```

`only` and `except` must contain names from the supported-pattern table below.
Unknown names throw a `RangeError` listing the valid names, even for empty or non-string input.
For example, `{ only: ['emial'] }` throws instead of silently leaving email addresses visible.
`labels` keys are validated too: pattern names and normalized sensitive key names such as `password` are accepted.
This validation applies to both `redact` and `redactObject`.

Date, RegExp and other non-plain objects pass through unchanged — only plain objects, arrays and strings are rebuilt.

### `findSensitive(text, options?)`

Returns what would be redacted, without changing the text. Results are sorted by position in the text, each with its start `index`:

```js
findSensitive('mail a@b.com, card 4111111111111111');
// [
//   { type: 'email', value: 'a@b.com', index: 5 },
//   { type: 'creditCard', value: '4111111111111111', index: 19 },
// ]

// Only look for one type, like redact():
findSensitive('mail a@b.com, card 4111111111111111', { only: ['email'] });
// [{ type: 'email', value: 'a@b.com', index: 5 }]
```

## What is redacted

| Type | Example |
| --- | --- |
| Email | `ana@example.com` → `[EMAIL]` |
| Phone | `+1 555-123-4567`, `+91 98765 43210` → `[PHONE]` |
| Credit card | Luhn-validated, 13–19 digits → `[CARD]` |
| IBAN | Country length and checksum validated, `DE89 3704 0044 0532 0130 00` → `[IBAN]` |
| API keys | GitHub `ghp_…`, OpenAI `sk-…` / `sk-proj-…` / `sk-svcacct-…`, Stripe `sk_live_…` / `sk_test_…` / `rk_live_…` / `rk_test_…`, AWS `AKIA…` / `ASIA…`, Slack `xoxb-…` / `xoxe-…` → `[TOKEN]` / `[API_KEY]` |
| JWT | `eyJ…` → `[TOKEN]` |
| Private key blocks | `-----BEGIN PRIVATE KEY-----` (also `ENCRYPTED`, `RSA`, `EC`, … and truncated blocks with no `END` line) → `[PRIVATE_KEY]` |
| SSN | `123-45-6789` → `[SSN]` |
| Indian PAN | `ABCDE1234F` → `[PAN]` |
| IPv4 | `203.0.113.42` → `[IP]` |
| URL passwords | `https://user:pass@host` → `https://user:[PASSWORD]@host` |
| Connection strings | `mongodb://user:pass@host`, `postgres://user:pass@host`, `redis://:pass@host` → password only → `[PASSWORD]` |
| URL query-string secrets | `?token=abc123&user=ana` → `?token=[TOKEN]&user=ana` |
| Authorization headers | `Authorization: Bearer abc` → `Authorization: Bearer [TOKEN]`; `Basic …` → `[CREDENTIALS]` |
| `key = value` secrets | `api_key = abc123…`, `aws_secret_access_key = …` → `api_key = [API_KEY]` |

Secrets in a URL query string are redacted only when the parameter name is a known secret name (`token`, `access_token`, `refresh_token`, `id_token`, `api_key`, `secret`, `client_secret`, `auth`, `authorization`, `password`, `passwd`, `pwd`, `session`, `sessionid`, with `_`/`-`/camelCase variants). Other parameters are left alone, as are similar-looking names such as `mytoken`. The label follows the parameter: tokens → `[TOKEN]`, API keys → `[API_KEY]`, secrets → `[SECRET]`, passwords → `[PASSWORD]`.

`Authorization` and `Proxy-Authorization` headers are redacted only for the `Bearer` and `Basic` schemes — the header name and scheme stay readable, only the credential is replaced. Other schemes (`Negotiate`, `Digest`, …) are left alone: their tokens are session-bound challenge responses, not reusable static credentials.

Credit cards are only redacted when they pass the Luhn check, so a random 16-digit order number is left alone. Phone numbers need at least 7 digits. Indian PAN numbers are matched in their five-letter, four-digit, one-letter form.

## What this is not

This is a safety net, not a guarantee. No pattern list can catch every secret in every format, and redaction happens after the secret already exists in memory. Treat it as one layer: keep real secrets out of logs in the first place, rotate any secret that was ever logged, and never rely on redaction alone for compliance.

## Contributing

Contributions are welcome — especially new redaction patterns. See [CONTRIBUTING.md](CONTRIBUTING.md). Good first issues are labelled `good first issue`.

## Contributors

redact-sensitive exists thanks to everyone who has contributed code, fixes and ideas — this wall grows on its own as new pull requests land:

<a href="https://github.com/sharkohark1234/redact-sensitive/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=sharkohark1234/redact-sensitive" alt="contributors" />
</a>

## License

MIT. See [LICENSE](LICENSE).

