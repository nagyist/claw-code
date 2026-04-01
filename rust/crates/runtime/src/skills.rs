use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SkillDiscoverySource {
    ProjectCodex,
    ProjectClaw,
    UserCodexHome,
    UserCodex,
    UserClaw,
}

impl SkillDiscoverySource {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ProjectCodex => "Project (.codex)",
            Self::ProjectClaw => "Project (.claw)",
            Self::UserCodexHome => "User ($CODEX_HOME)",
            Self::UserCodex => "User (~/.codex)",
            Self::UserClaw => "User (~/.claw)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillRootKind {
    SkillsDir,
    LegacyCommandsDir,
}

impl SkillRootKind {
    #[must_use]
    pub const fn detail_label(self) -> Option<&'static str> {
        match self {
            Self::SkillsDir => None,
            Self::LegacyCommandsDir => Some("legacy /commands"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillDiscoveryRoot {
    pub source: SkillDiscoverySource,
    pub path: PathBuf,
    pub kind: SkillRootKind,
}

pub fn discover_skill_roots(cwd: &Path) -> Vec<SkillDiscoveryRoot> {
    let mut roots = Vec::new();

    for ancestor in cwd.ancestors() {
        push_unique_skill_root(
            &mut roots,
            SkillDiscoverySource::ProjectCodex,
            ancestor.join(".codex").join("skills"),
            SkillRootKind::SkillsDir,
        );
        push_unique_skill_root(
            &mut roots,
            SkillDiscoverySource::ProjectClaw,
            ancestor.join(".claw").join("skills"),
            SkillRootKind::SkillsDir,
        );
        push_unique_skill_root(
            &mut roots,
            SkillDiscoverySource::ProjectCodex,
            ancestor.join(".codex").join("commands"),
            SkillRootKind::LegacyCommandsDir,
        );
        push_unique_skill_root(
            &mut roots,
            SkillDiscoverySource::ProjectClaw,
            ancestor.join(".claw").join("commands"),
            SkillRootKind::LegacyCommandsDir,
        );
    }

    if let Ok(codex_home) = env::var("CODEX_HOME") {
        let codex_home = PathBuf::from(codex_home);
        push_unique_skill_root(
            &mut roots,
            SkillDiscoverySource::UserCodexHome,
            codex_home.join("skills"),
            SkillRootKind::SkillsDir,
        );
        push_unique_skill_root(
            &mut roots,
            SkillDiscoverySource::UserCodexHome,
            codex_home.join("commands"),
            SkillRootKind::LegacyCommandsDir,
        );
    }

    if let Some(home) = env::var_os("HOME") {
        let home = PathBuf::from(home);
        push_unique_skill_root(
            &mut roots,
            SkillDiscoverySource::UserCodex,
            home.join(".codex").join("skills"),
            SkillRootKind::SkillsDir,
        );
        push_unique_skill_root(
            &mut roots,
            SkillDiscoverySource::UserCodex,
            home.join(".codex").join("commands"),
            SkillRootKind::LegacyCommandsDir,
        );
        push_unique_skill_root(
            &mut roots,
            SkillDiscoverySource::UserClaw,
            home.join(".claw").join("skills"),
            SkillRootKind::SkillsDir,
        );
        push_unique_skill_root(
            &mut roots,
            SkillDiscoverySource::UserClaw,
            home.join(".claw").join("commands"),
            SkillRootKind::LegacyCommandsDir,
        );
    }

    roots
}

pub fn resolve_skill_path(skill: &str, cwd: &Path) -> Result<PathBuf, String> {
    let requested = normalize_requested_skill_name(skill)?;

    for root in discover_skill_roots(cwd) {
        match root.kind {
            SkillRootKind::SkillsDir => {
                let direct = root.path.join(&requested).join("SKILL.md");
                if direct.is_file() {
                    return Ok(direct);
                }

                if let Ok(entries) = std::fs::read_dir(&root.path) {
                    for entry in entries.flatten() {
                        let path = entry.path().join("SKILL.md");
                        if !path.is_file() {
                            continue;
                        }
                        if entry
                            .file_name()
                            .to_string_lossy()
                            .eq_ignore_ascii_case(&requested)
                        {
                            return Ok(path);
                        }
                    }
                }
            }
            SkillRootKind::LegacyCommandsDir => {
                let direct_markdown = root.path.join(format!("{requested}.md"));
                if direct_markdown.is_file() {
                    return Ok(direct_markdown);
                }

                let direct_skill_dir = root.path.join(&requested).join("SKILL.md");
                if direct_skill_dir.is_file() {
                    return Ok(direct_skill_dir);
                }

                if let Ok(entries) = std::fs::read_dir(&root.path) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            let skill_path = path.join("SKILL.md");
                            if !skill_path.is_file() {
                                continue;
                            }
                            if entry
                                .file_name()
                                .to_string_lossy()
                                .eq_ignore_ascii_case(&requested)
                            {
                                return Ok(skill_path);
                            }
                            continue;
                        }

                        if !path
                            .extension()
                            .is_some_and(|ext| ext.to_string_lossy().eq_ignore_ascii_case("md"))
                        {
                            continue;
                        }

                        let Some(stem) = path.file_stem() else {
                            continue;
                        };
                        if stem.to_string_lossy().eq_ignore_ascii_case(&requested) {
                            return Ok(path);
                        }
                    }
                }
            }
        }
    }

    Err(format!("unknown skill: {requested}"))
}

fn normalize_requested_skill_name(skill: &str) -> Result<String, String> {
    let requested = skill.trim().trim_start_matches('/').trim_start_matches('$');
    if requested.is_empty() {
        return Err(String::from("skill must not be empty"));
    }
    Ok(requested.to_string())
}

fn push_unique_skill_root(
    roots: &mut Vec<SkillDiscoveryRoot>,
    source: SkillDiscoverySource,
    path: PathBuf,
    kind: SkillRootKind,
) {
    if path.is_dir() && !roots.iter().any(|existing| existing.path == path) {
        roots.push(SkillDiscoveryRoot { source, path, kind });
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        discover_skill_roots, resolve_skill_path, SkillDiscoveryRoot, SkillDiscoverySource,
        SkillRootKind,
    };

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("runtime-skills-{label}-{nanos}"))
    }

    fn write_skill(root: &Path, name: &str) {
        let skill_root = root.join(name);
        fs::create_dir_all(&skill_root).expect("skill root");
        fs::write(skill_root.join("SKILL.md"), format!("# {name}\n")).expect("write skill");
    }

    fn write_legacy_markdown(root: &Path, name: &str) {
        fs::create_dir_all(root).expect("legacy root");
        fs::write(root.join(format!("{name}.md")), format!("# {name}\n")).expect("write command");
    }

    #[test]
    fn discovers_workspace_and_user_skill_roots() {
        let _guard = crate::test_env_lock();
        let workspace = temp_dir("workspace");
        let nested = workspace.join("apps").join("ui");
        let user_home = temp_dir("home");

        fs::create_dir_all(&nested).expect("nested cwd");
        fs::create_dir_all(workspace.join(".codex").join("skills")).expect("project codex skills");
        fs::create_dir_all(workspace.join(".claw").join("commands"))
            .expect("project claw commands");
        fs::create_dir_all(user_home.join(".codex").join("skills")).expect("user codex skills");

        std::env::set_var("HOME", &user_home);
        std::env::remove_var("CODEX_HOME");

        let roots = discover_skill_roots(&nested);

        assert!(roots.contains(&SkillDiscoveryRoot {
            source: SkillDiscoverySource::ProjectCodex,
            path: workspace.join(".codex").join("skills"),
            kind: SkillRootKind::SkillsDir,
        }));
        assert!(roots.contains(&SkillDiscoveryRoot {
            source: SkillDiscoverySource::ProjectClaw,
            path: workspace.join(".claw").join("commands"),
            kind: SkillRootKind::LegacyCommandsDir,
        }));
        assert!(roots.contains(&SkillDiscoveryRoot {
            source: SkillDiscoverySource::UserCodex,
            path: user_home.join(".codex").join("skills"),
            kind: SkillRootKind::SkillsDir,
        }));

        std::env::remove_var("HOME");
        let _ = fs::remove_dir_all(workspace);
        let _ = fs::remove_dir_all(user_home);
    }

    #[test]
    fn resolves_workspace_skills_and_legacy_commands() {
        let _guard = crate::test_env_lock();
        let workspace = temp_dir("resolve");
        let nested = workspace.join("apps").join("ui");
        let original_dir = std::env::current_dir().expect("cwd");

        fs::create_dir_all(&nested).expect("nested cwd");
        write_skill(&workspace.join(".claw").join("skills"), "review");
        write_legacy_markdown(&workspace.join(".codex").join("commands"), "deploy");

        std::env::set_current_dir(&nested).expect("set cwd");
        let review = resolve_skill_path("review", &nested).expect("workspace skill");
        let deploy = resolve_skill_path("/deploy", &nested).expect("legacy command");
        std::env::set_current_dir(&original_dir).expect("restore cwd");

        assert!(review.ends_with(".claw/skills/review/SKILL.md"));
        assert!(deploy.ends_with(".codex/commands/deploy.md"));

        let _ = fs::remove_dir_all(workspace);
    }
}
