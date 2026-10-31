use super::*;
use serde_json::json;

struct Env(&'static str, Option<std::ffi::OsString>);

impl Env {
    fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let previous = std::env::var_os(key);
        crate::env::set_var(key, value);
        Self(key, previous)
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        match self.1.take() {
            Some(value) => crate::env::set_var(self.0, value),
            None => crate::env::remove_var(self.0),
        }
    }
}

fn home() -> (tempfile::TempDir, Env) {
    let dir = tempfile::tempdir().unwrap();
    let env = Env::set("JCODE_HOME", dir.path());
    (dir, env)
}

fn git_repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".git")).unwrap();
    dir
}

#[test]
fn digest_is_stable_across_key_order_and_prefixed() {
    let a = json!({"b": [1, {"y": 1, "x": 2}], "a": "z"});
    let b = json!({"a": "z", "b": [1, {"x": 2, "y": 1}]});
    assert_eq!(digest_json(&a), digest_json(&b));
    assert!(digest_json(&a).starts_with("sha256:"));
    assert_ne!(digest_json(&a), digest_json(&json!({"a": "z"})));
    assert_eq!(canonical_json(&a), r#"{"a":"z","b":[1,{"x":2,"y":1}]}"#);
}

#[test]
fn grant_check_and_change_detection() {
    let _lock = crate::storage::lock_test_env();
    let (_home, _env) = home();
    let project = git_repo();
    let path = project.path();
    assert_eq!(
        trust_state(path, Scope::Hooks, "sha256:a").unwrap(),
        TrustState::Untrusted
    );
    grant(path, Scope::Hooks, "sha256:a").unwrap();
    assert!(is_trusted(path, Scope::Hooks, "sha256:a"));
    assert_eq!(
        trust_state(path, Scope::Hooks, "sha256:b").unwrap(),
        TrustState::Changed
    );
    assert!(!is_trusted(path, Scope::Hooks, "sha256:b"));
}

#[test]
fn scopes_are_independent() {
    let _lock = crate::storage::lock_test_env();
    let (_home, _env) = home();
    let project = git_repo();
    grant(project.path(), Scope::Mcp, "sha256:m").unwrap();
    assert!(is_trusted(project.path(), Scope::Mcp, "sha256:m"));
    assert!(!is_trusted(project.path(), Scope::Hooks, "sha256:m"));
    assert!(!is_trusted(project.path(), Scope::Agents, "sha256:m"));
    grant(project.path(), Scope::Hooks, "sha256:h").unwrap();
    assert!(revoke(project.path(), Some(Scope::Hooks)).unwrap());
    assert!(is_trusted(project.path(), Scope::Mcp, "sha256:m"));
    assert!(!revoke(project.path(), Some(Scope::Hooks)).unwrap());
    assert!(revoke(project.path(), None).unwrap());
    assert!(!is_trusted(project.path(), Scope::Mcp, "sha256:m"));
    assert!(list().is_empty());
}

#[test]
fn subdirectories_share_the_git_root_key() {
    let _lock = crate::storage::lock_test_env();
    let (_home, _env) = home();
    let project = git_repo();
    let nested = project.path().join("a/b");
    std::fs::create_dir_all(&nested).unwrap();
    grant(&nested, Scope::Hooks, "sha256:x").unwrap();
    assert!(is_trusted(project.path(), Scope::Hooks, "sha256:x"));
    assert_eq!(
        project_root(&nested).unwrap(),
        std::fs::canonicalize(project.path()).unwrap()
    );
}

fn linked_worktree(main: &Path) -> tempfile::TempDir {
    // Mimic `git worktree add`: <main>/.git/worktrees/wt with a commondir file,
    // and a worktree whose `.git` file points at it.
    let admin = main.join(".git/worktrees/wt");
    std::fs::create_dir_all(&admin).unwrap();
    std::fs::write(admin.join("commondir"), "../..\n").unwrap();
    let worktree = tempfile::tempdir().unwrap();
    std::fs::write(
        worktree.path().join(".git"),
        format!("gitdir: {}\n", admin.display()),
    )
    .unwrap();
    worktree
}

#[test]
fn linked_worktree_keys_on_main_checkout_but_digest_must_match() {
    let _lock = crate::storage::lock_test_env();
    let (_home, _env) = home();
    let main = git_repo();
    let worktree = linked_worktree(main.path());
    assert_eq!(
        project_root(worktree.path()).unwrap(),
        std::fs::canonicalize(main.path()).unwrap()
    );
    grant(main.path(), Scope::Hooks, "sha256:same").unwrap();
    assert!(is_trusted(worktree.path(), Scope::Hooks, "sha256:same"));
    assert!(!is_trusted(worktree.path(), Scope::Hooks, "sha256:edited"));
    assert_eq!(
        trust_state(worktree.path(), Scope::Hooks, "sha256:edited").unwrap(),
        TrustState::Changed
    );
}

#[test]
fn unusable_store_fails_closed_and_is_not_overwritten() {
    let _lock = crate::storage::lock_test_env();
    let (_home, _env) = home();
    let project = git_repo();
    grant(project.path(), Scope::Hooks, "sha256:a").unwrap();
    let path = store_path();

    std::fs::write(&path, "{ not json").unwrap();
    assert!(!is_trusted(project.path(), Scope::Hooks, "sha256:a"));
    assert!(grant(project.path(), Scope::Hooks, "sha256:a").is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "{ not json");

    std::fs::write(&path, r#"{"version":99,"projects":{}}"#).unwrap();
    assert!(!is_trusted(project.path(), Scope::Hooks, "sha256:a"));
    assert!(revoke(project.path(), None).is_err());
}

#[test]
fn missing_project_directory_is_untrusted_not_a_panic() {
    let _lock = crate::storage::lock_test_env();
    let (_home, _env) = home();
    assert!(!is_trusted(
        Path::new("/nonexistent/jcode/trust/path"),
        Scope::Hooks,
        "sha256:a"
    ));
}

#[test]
fn safe_terminal_text_escapes_control_and_invisible_characters() {
    assert_eq!(safe_terminal_text("ok"), "ok");
    assert_eq!(safe_terminal_text("a\u{1b}[31mb"), "a\\u{1b}[31mb");
    assert_eq!(safe_terminal_text("x\u{202e}y"), "x\\u{202e}y");
}
