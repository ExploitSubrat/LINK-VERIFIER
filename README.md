# LinkLens — URL Safety Analyzer

LinkLens is a beginner-friendly, browser-based URL analyzer. It checks URL formatting and a small set of visible warning indicators locally in your browser.

## Features

- URL format validation
- HTTP/HTTPS indicator
- Warnings for selected suspicious URL patterns
- Recent scan history stored in the current browser
- Responsive layout for mobile and desktop
- No API key or build tools required

## Project structure

```text
linklens/
├── index.html
├── css/
│   └── style.css
├── js/
│   └── app.js
├── assets/
│   └── images/
│       └── .gitkeep
├── README.md
├── .gitignore
└── LICENSE
```

## Run locally

Open `index.html` in a modern browser. For GitHub Pages, publish from the `main` branch and the repository root (`/(root)`).

## Publish with GitHub Pages

1. Open your repository's **Settings**.
2. Select **Pages**.
3. Under **Build and deployment**, choose **Deploy from a branch**.
4. Choose branch `main` and folder `/(root)`, then save.
5. Wait for the published site link to appear in the Pages section.

## Important safety note

LinkLens is an educational rule-based checker, not an antivirus or a reputation service. It does not visit or verify the target website. HTTPS does not prove that a site is trustworthy, and a low-warning result is not a guarantee of safety. Do not enter passwords or private tokens into untrusted websites.

## Privacy

The current version performs checks in the browser and stores recent scan history in that browser's local storage. Clearing browser data may remove that history.
