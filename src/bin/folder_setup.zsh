#!/usr/bin/env zsh

# auth-lib project scaffold
# safe to re-run: creates files/dirs only if they don't already exist

setopt ERR_EXIT

ROOT=${1:-.}

dirs=(
  $ROOT/initial_setup
  $ROOT/src/interfaces
  $ROOT/src/model/migrations
  $ROOT/src/auth
  $ROOT/src/storage
  $ROOT/src/utils
  $ROOT/src/bin
)

files=(
  $ROOT/Cargo.toml
  $ROOT/Cargo.lock
  $ROOT/env.example
  $ROOT/initial_setup/README.md
  $ROOT/src/lib.rs
  $ROOT/src/main.rs
  $ROOT/src/interfaces/mod.rs
  $ROOT/src/interfaces/auth.rs
  $ROOT/src/interfaces/user_repo.rs
  $ROOT/src/interfaces/session_repo.rs
  $ROOT/src/interfaces/role_repo.rs
  $ROOT/src/model/mod.rs
  $ROOT/src/model/user.rs
  $ROOT/src/model/session.rs
  $ROOT/src/model/role.rs
  $ROOT/src/model/migrations/0001_init.postgres.sql
  $ROOT/src/model/migrations/0001_init.mysql.sql
  $ROOT/src/auth/mod.rs
  $ROOT/src/auth/service.rs
  $ROOT/src/auth/jwt.rs
  $ROOT/src/auth/password.rs
  $ROOT/src/storage/mod.rs
  $ROOT/src/storage/pool.rs
  $ROOT/src/storage/user_repo.rs
  $ROOT/src/storage/session_repo.rs
  $ROOT/src/storage/role_repo.rs
  $ROOT/src/utils/mod.rs
  $ROOT/src/utils/config.rs
  $ROOT/src/utils/helpers.rs
  $ROOT/src/bin/setup_db.rs
)

echo
echo "  auth-lib scaffold"
echo "  root: $(realpath $ROOT)"
echo

for d in $dirs; do
  if [[ ! -d $d ]]; then
    mkdir -p $d
    echo "  + dir   $d"
  else
    echo "  ~ skip  $d"
  fi
done

echo

for f in $files; do
  if [[ ! -f $f ]]; then
    touch $f
    echo "  + file  $f"
  else
    echo "  ~ skip  $f"
  fi
done

echo
echo "  done."
echo