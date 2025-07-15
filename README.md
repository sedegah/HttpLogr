# HttpLogr

HttpLogr is a Python-based CLI tool for tracing websites and logging detailed network, SSL, and server metadata. It identifies redirect chains, extracts SSL certificate info, performs geolocation lookups, and detects if a site is static, WordPress-based, or AI-generated.

## 🚀 Features

- Trace full HTTP redirect chains
- View all response headers
- Fetch SSL certificate issuer, subject, validity dates
- Resolve domain to IP address
- Optional IP geolocation (via ip-api)
- Detect tech stack: WordPress / AI-generated / static site
- Export to `.txt`, `.json`, or `.md`
- Verbose console logging

## 📦 Installation

```bash
git clone https://github.com/yourusername/HttpLogr.git
cd HttpLogr
python -m venv venv
venv\Scripts\activate   # or source venv/bin/activate on Unix
pip install -r requirements.txt
````

## 🛠 Requirements

* Python 3.7+
* `requests`
* `beautifulsoup4`

Install via:

```bash
pip install -r requirements.txt
```

## 📌 Usage

```bash
python httptrace.py <url> [--geo] [--export json|markdown] [--verbose]
```

### Examples

```bash
python httptrace.py https://example.com
python httptrace.py http://xlabsgh.com --geo
python httptrace.py https://myai.site --verbose --export markdown
```

## 📤 Output

Depending on the domain, output is saved as:

* `example_com.txt`
* `example_com.json`
* `example_com.md`

Example fields:

* Redirect Chain
* Response Headers
* Resolved IP
* SSL Certificate Info
* Site Technology
* Geolocation (if enabled)

## 🧠 Site Type Detection

HttpLogr makes an intelligent guess:

* **WordPress**: Detects `wp-content`, `wp-includes`, or WordPress generator meta
* **AI-generated**: Detects platforms like Framer, Durable, Webflow
* **Likely Static**: Very few lines of HTML with simple structure
* **Unknown**: Fallback if no strong indicators are found

## 🌐 Geolocation

Uses `ip-api.com` to map IP → Country, Region, City, ISP
This is optional via `--geo` flag.

## 📄 License

MIT License

## 🙋‍♂️ Author

Developed by [Kimathi Elikplim Sedegah](https://kimathisedegah.vercel.app)

