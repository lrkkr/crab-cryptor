set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]

alias p := push
alias c := check
alias i := install

default:
  @just --list

# run server
dev:
  cargo watch -x "run"

# git add, commit and push
push MESSAGE:
  git cliff --with-commit "{{ MESSAGE }}" -o CHANGELOG.md
  git add .
  git commit -m "{{ MESSAGE }}"
  git push

tag TAG:
  git tag {{ TAG }}
  git push origin {{ TAG }}

del_tag TAG:
  git tag -d {{ TAG }}
  git push origin :refs/tags/{{ TAG }}

del_branch BRANCH:
  git branch -d {{ BRANCH }}

check:
  pre-commit run --all-files

install:
  cargo install --path .

test:
  cargo test -- --nocapture
