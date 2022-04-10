- scan compressed file/folder
- encode creds if force commit
  - run scan
  - if credentials detected, prompt user to force commit or not
    - if ```diff
      - yes 
      ```:
      - then set FLAG_FORCE_COMMIT = True
      - encode all creds string
      - git add -> commit leads to re-scan (habit of pre-commit)
      - check if FLAG_FORCE_COMMIT = True, decode creds to original string
      - set FLAG_FORCE_COMMIT = False, then exit 0
      - git push by user

    - if ![#f03c15]no `#f03c15`:
      - then git push by user