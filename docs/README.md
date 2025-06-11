# RustySocks Documentation

This directory contains the source for the RustySocks documentation site.

## Building Locally

1. Install mdBook:
```bash
cargo install mdbook mdbook-mermaid
```

2. Build the documentation:
```bash
cd docs
mdbook build
```

3. Serve locally:
```bash
mdbook serve --open
```

The documentation will be available at `http://localhost:3000`.

## Structure

- `book.toml` - mdBook configuration
- `src/` - Documentation source files
  - `SUMMARY.md` - Table of contents
  - Individual `.md` files for each page

## Contributing

When adding new documentation:

1. Add your page to `src/SUMMARY.md`
2. Create the corresponding `.md` file
3. Follow the existing style and formatting
4. Test locally before submitting PR

## Deployment

Documentation is automatically deployed to GitHub Pages when changes are pushed to the main branch.