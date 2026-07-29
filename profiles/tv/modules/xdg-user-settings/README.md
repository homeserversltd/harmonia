# xdg-user-settings

TV XDG user settings and launcher files live inside this module under `files_root/<intent>/...`. The intent folders are `kde-applications`, `launcher-bin`, `portal`, and `wofi`.

`launcher-cache-refresh` runs after this module has converged the launcher scripts and their XDG inputs.

Do not create sibling `profiles/tv/config` payload folders. Profile files belong in the module that owns the intent.
