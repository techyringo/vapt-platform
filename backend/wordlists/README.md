# Wordlists

The bundled files are compact, high-signal starter lists. They are suitable for
smoke tests and light default scans, but they are not enough for deep production
VAPT coverage.

For product scans, mount a curated corpus into `/app/wordlists`, or set
`VAPT_WORDLIST_HOST_DIR` to a host directory that contains your approved lists.
Recommended layout:

- `common-web.txt`: high-signal directories/files for normal web discovery
- `api-web.txt`: API routes, versions, OpenAPI/Swagger paths, auth endpoints
- `api-routes.txt`: extra API route candidates used by web/API sweeps
- `cms-web.txt`: CMS/plugin/theme paths
- `sensitive-files.txt`: env/config/backup/source-control exposure candidates
- `s3-buckets.txt`: S3 bucket name patterns consumed by the CloudAgent
- `seclists/`: optional large corpus such as SecLists, used by advanced scan
  profiles after preflight confirms the files exist

Do not blindly run huge lists against every target. The scheduler should select
wordlists based on detected technology, scan mode, target responsiveness, and
authorization scope.
