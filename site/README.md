# Argos Static Site

This folder contains the static product splash page and user guide for the Argos
rescue wallet subdomain.

## Files

- `index.html`: product splash page
- `guide.html`: user guide
- `styles.css`: shared site styles
- `assets/zeck-icon.svg`: blue key-glyph product icon — used directly as the site favicon and header icon
- `assets/zeck-icon.png`: legacy raster icon (no longer referenced; the `.svg` is used directly)
- `assets/sovright-logo-caption.svg`: Sovright caption wordmark used in the header
- `assets/zeck-og.png`: 1200x630 Open Graph and Twitter Card preview image
- `assets/zeck-og.svg`: editable source for the social preview image
- `CNAME`: GitHub Pages custom-domain hint for `argos.sovright.com`

## Hosting

The site is static and can be served from any CDN or static host. For GitHub
Pages, publish the `site/` directory and keep `CNAME` set to the target
subdomain. For Cloudflare Pages, Netlify, or Vercel, set the publish directory
to `site` and configure the DNS record for `argos.sovright.com`.

Update the download links in `index.html` once release assets are signed and
published.
