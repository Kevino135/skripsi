- scan compressed file/folder
- encode creds if force commit
  - run scan
  - if credentials detected, prompt user to force commit or not
    - if ![#f03c15] `yes`:
      - then set FLAG_FORCE_COMMIT = True
      - encode all creds string
      - git add -> commit leads to re-scan (habit of pre-commit)
      - check if FLAG_FORCE_COMMIT = True, decode creds to original string
      - set FLAG_FORCE_COMMIT = False, then exit 0
      - git push by user

    - if ![#c5f015] `no`:
      - then git push by user