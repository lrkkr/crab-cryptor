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
  git add .
  git commit -m "{{ MESSAGE }}"
  git push

check:
  pre-commit run --all-files

install:
  cargo install --path .
