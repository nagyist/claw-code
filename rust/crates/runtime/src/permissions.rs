use std::collections::BTreeMap;

use serde_json::Value;

use crate::config::RuntimePermissionRuleConfig;


/// Machine-readable policy exception scope that an approval token may override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalScope {
    pub policy: String,
    pub action: String,
    pub repository: Option<String>,
    pub branch: Option<String>,

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

impl ApprovalScope {
    #[must_use]
    pub fn new(policy: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            policy: policy.into(),
            action: action.into(),
            repository: None,
            branch: None,
        }
    }

    #[must_use]
    pub fn with_repository(mut self, repository: impl Into<String>) -> Self {
        self.repository = Some(repository.into());
        self
    }

    #[must_use]
    pub fn with_branch(mut self, branch: impl Into<String>) -> Self {
        self.branch = Some(branch.into());
        self
    }

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

/// Actor/session hop recorded when an approval is delegated or consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDelegationHop {
    pub actor: String,
    pub session_id: Option<String>,
    pub reason: String,

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

impl ApprovalDelegationHop {
    #[must_use]
    pub fn new(actor: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            actor: actor.into(),
            session_id: None,
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

/// Current lifecycle state for a policy-exception approval token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalTokenStatus {
    Pending,
    Granted,
    Consumed,
    Expired,
    Revoked,

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

impl ApprovalTokenStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "approval_pending",
            Self::Granted => "approval_granted",
            Self::Consumed => "approval_consumed",
            Self::Expired => "approval_expired",
            Self::Revoked => "approval_revoked",
        }
    }

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

/// Typed policy errors returned when a token cannot authorize a blocked action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalTokenError {
    NoApproval,
    ApprovalPending,
    ApprovalExpired,
    ApprovalRevoked,
    ApprovalAlreadyConsumed,
    ScopeMismatch { expected: ApprovalScope, actual: ApprovalScope },
    UnauthorizedDelegate { expected: String, actual: String },

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

impl ApprovalTokenError {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoApproval => "no_approval",
            Self::ApprovalPending => "approval_pending",
            Self::ApprovalExpired => "approval_expired",
            Self::ApprovalRevoked => "approval_revoked",
            Self::ApprovalAlreadyConsumed => "approval_already_consumed",
            Self::ScopeMismatch { .. } => "approval_scope_mismatch",
            Self::UnauthorizedDelegate { .. } => "approval_unauthorized_delegate",
        }
    }

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

/// Approval grant bound to a policy/action scope, approving owner, and executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalTokenGrant {
    pub token: String,
    pub scope: ApprovalScope,
    pub approving_actor: String,
    pub approved_executor: String,
    pub status: ApprovalTokenStatus,
    pub expires_at_epoch_seconds: Option<u64>,
    pub max_uses: u32,
    pub uses: u32,
    delegation_chain: Vec<ApprovalDelegationHop>,

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

impl ApprovalTokenGrant {
    #[must_use]
    pub fn pending(
        token: impl Into<String>,
        scope: ApprovalScope,
        approving_actor: impl Into<String>,
        approved_executor: impl Into<String>,
    ) -> Self {
        Self {
            token: token.into(),
            scope,
            approving_actor: approving_actor.into(),
            approved_executor: approved_executor.into(),
            status: ApprovalTokenStatus::Pending,
            expires_at_epoch_seconds: None,
            max_uses: 1,
            uses: 0,
            delegation_chain: Vec::new(),
        }
    }

    #[must_use]
    pub fn granted(
        token: impl Into<String>,
        scope: ApprovalScope,
        approving_actor: impl Into<String>,
        approved_executor: impl Into<String>,
    ) -> Self {
        Self::pending(token, scope, approving_actor, approved_executor).approve()
    }

    #[must_use]
    pub fn approve(mut self) -> Self {
        self.status = ApprovalTokenStatus::Granted;
        self
    }

    #[must_use]
    pub fn expires_at(mut self, epoch_seconds: u64) -> Self {
        self.expires_at_epoch_seconds = Some(epoch_seconds);
        self
    }

    #[must_use]
    pub fn with_max_uses(mut self, max_uses: u32) -> Self {
        self.max_uses = max_uses.max(1);
        self
    }

    #[must_use]
    pub fn with_delegation_hop(mut self, hop: ApprovalDelegationHop) -> Self {
        self.delegation_chain.push(hop);
        self
    }

    #[must_use]
    pub fn delegation_chain(&self) -> &[ApprovalDelegationHop] {
        &self.delegation_chain
    }

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

/// Auditable result of verifying or consuming an approval token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalTokenAudit {
    pub token: String,
    pub scope: ApprovalScope,
    pub approving_actor: String,
    pub executing_actor: String,
    pub status: ApprovalTokenStatus,
    pub delegated_execution: bool,
    pub delegation_chain: Vec<ApprovalDelegationHop>,
    pub uses: u32,
    pub max_uses: u32,

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

/// In-memory approval-token ledger with one-time-use and replay protection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApprovalTokenLedger {
    grants: BTreeMap<String, ApprovalTokenGrant>,

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

impl ApprovalTokenLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, grant: ApprovalTokenGrant) {
        self.grants.insert(grant.token.clone(), grant);
    }

    #[must_use]
    pub fn get(&self, token: &str) -> Option<&ApprovalTokenGrant> {
        self.grants.get(token)
    }

    pub fn revoke(&mut self, token: &str) -> Result<ApprovalTokenAudit, ApprovalTokenError> {
        let grant = self
            .grants
            .get_mut(token)
            .ok_or(ApprovalTokenError::NoApproval)?;
        grant.status = ApprovalTokenStatus::Revoked;
        Ok(Self::audit_for(grant, &grant.approved_executor))
    }

    pub fn verify(
        &self,
        token: &str,
        scope: &ApprovalScope,
        executing_actor: &str,
        now_epoch_seconds: u64,
    ) -> Result<ApprovalTokenAudit, ApprovalTokenError> {
        let grant = self.grants.get(token).ok_or(ApprovalTokenError::NoApproval)?;
        Self::validate_grant(grant, scope, executing_actor, now_epoch_seconds)?;
        Ok(Self::audit_for(grant, executing_actor))
    }

    pub fn consume(
        &mut self,
        token: &str,
        scope: &ApprovalScope,
        executing_actor: &str,
        now_epoch_seconds: u64,
    ) -> Result<ApprovalTokenAudit, ApprovalTokenError> {
        let grant = self
            .grants
            .get_mut(token)
            .ok_or(ApprovalTokenError::NoApproval)?;
        Self::validate_grant(grant, scope, executing_actor, now_epoch_seconds)?;
        grant.uses += 1;
        if grant.uses >= grant.max_uses {
            grant.status = ApprovalTokenStatus::Consumed;
        }
        Ok(Self::audit_for(grant, executing_actor))
    }

    fn validate_grant(
        grant: &ApprovalTokenGrant,
        scope: &ApprovalScope,
        executing_actor: &str,
        now_epoch_seconds: u64,
    ) -> Result<(), ApprovalTokenError> {
        match grant.status {
            ApprovalTokenStatus::Pending => return Err(ApprovalTokenError::ApprovalPending),
            ApprovalTokenStatus::Consumed => return Err(ApprovalTokenError::ApprovalAlreadyConsumed),
            ApprovalTokenStatus::Expired => return Err(ApprovalTokenError::ApprovalExpired),
            ApprovalTokenStatus::Revoked => return Err(ApprovalTokenError::ApprovalRevoked),
            ApprovalTokenStatus::Granted => {}
        }

        if grant
            .expires_at_epoch_seconds
            .is_some_and(|expires_at| now_epoch_seconds > expires_at)
        {
            return Err(ApprovalTokenError::ApprovalExpired);
        }

        if grant.uses >= grant.max_uses {
            return Err(ApprovalTokenError::ApprovalAlreadyConsumed);
        }

        if grant.scope != *scope {
            return Err(ApprovalTokenError::ScopeMismatch {
                expected: grant.scope.clone(),
                actual: scope.clone(),
            });
        }

        if grant.approved_executor != executing_actor {
            return Err(ApprovalTokenError::UnauthorizedDelegate {
                expected: grant.approved_executor.clone(),
                actual: executing_actor.to_string(),
            });
        }

        Ok(())
    }

    fn audit_for(grant: &ApprovalTokenGrant, executing_actor: &str) -> ApprovalTokenAudit {
        let mut delegation_chain = grant.delegation_chain.clone();
        if delegation_chain.is_empty() {
            delegation_chain.push(ApprovalDelegationHop::new(
                grant.approving_actor.clone(),
                "approval granted",
            ));
        }
        if grant.approving_actor != executing_actor
            && !delegation_chain.iter().any(|hop| hop.actor == executing_actor)
        {
            delegation_chain.push(ApprovalDelegationHop::new(
                executing_actor.to_string(),
                "delegated execution",
            ));
        }

        ApprovalTokenAudit {
            token: grant.token.clone(),
            scope: grant.scope.clone(),
            approving_actor: grant.approving_actor.clone(),
            executing_actor: executing_actor.to_string(),
            status: grant.status,
            delegated_execution: grant.approving_actor != executing_actor,
            delegation_chain,
            uses: grant.uses,
            max_uses: grant.max_uses,
        }
    }

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

/// Permission level assigned to a tool invocation or runtime session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PermissionMode {
    ReadOnly,
    WorkspaceWrite,
    DangerFullAccess,
    Prompt,
    Allow,

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

impl PermissionMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::WorkspaceWrite => "workspace-write",
            Self::DangerFullAccess => "danger-full-access",
            Self::Prompt => "prompt",
            Self::Allow => "allow",
        }
    }

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

/// Hook-provided override applied before standard permission evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionOverride {
    Allow,
    Deny,
    Ask,

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

/// Additional permission context supplied by hooks or higher-level orchestration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PermissionContext {
    override_decision: Option<PermissionOverride>,
    override_reason: Option<String>,

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

impl PermissionContext {
    #[must_use]
    pub fn new(
        override_decision: Option<PermissionOverride>,
        override_reason: Option<String>,
    ) -> Self {
        Self {
            override_decision,
            override_reason,
        }
    }

    #[must_use]
    pub fn override_decision(&self) -> Option<PermissionOverride> {
        self.override_decision
    }

    #[must_use]
    pub fn override_reason(&self) -> Option<&str> {
        self.override_reason.as_deref()
    }

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

/// Full authorization request presented to a permission prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionRequest {
    pub tool_name: String,
    pub input: String,
    pub current_mode: PermissionMode,
    pub required_mode: PermissionMode,
    pub reason: Option<String>,

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

/// User-facing decision returned by a [`PermissionPrompter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionPromptDecision {
    Allow,
    Deny { reason: String },

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

/// Prompting interface used when policy requires interactive approval.
pub trait PermissionPrompter {
    fn decide(&mut self, request: &PermissionRequest) -> PermissionPromptDecision;

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

/// Final authorization result after evaluating static rules and prompts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionOutcome {
    Allow,
    Deny { reason: String },

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

/// Evaluates permission mode requirements plus allow/deny/ask rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionPolicy {
    active_mode: PermissionMode,
    tool_requirements: BTreeMap<String, PermissionMode>,
    allow_rules: Vec<PermissionRule>,
    deny_rules: Vec<PermissionRule>,
    ask_rules: Vec<PermissionRule>,

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

impl PermissionPolicy {
    #[must_use]
    pub fn new(active_mode: PermissionMode) -> Self {
        Self {
            active_mode,
            tool_requirements: BTreeMap::new(),
            allow_rules: Vec::new(),
            deny_rules: Vec::new(),
            ask_rules: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_tool_requirement(
        mut self,
        tool_name: impl Into<String>,
        required_mode: PermissionMode,
    ) -> Self {
        self.tool_requirements
            .insert(tool_name.into(), required_mode);
        self
    }

    #[must_use]
    pub fn with_permission_rules(mut self, config: &RuntimePermissionRuleConfig) -> Self {
        self.allow_rules = config
            .allow()
            .iter()
            .map(|rule| PermissionRule::parse(rule))
            .collect();
        self.deny_rules = config
            .deny()
            .iter()
            .map(|rule| PermissionRule::parse(rule))
            .collect();
        self.ask_rules = config
            .ask()
            .iter()
            .map(|rule| PermissionRule::parse(rule))
            .collect();
        self
    }

    #[must_use]
    pub fn active_mode(&self) -> PermissionMode {
        self.active_mode
    }

    #[must_use]
    pub fn required_mode_for(&self, tool_name: &str) -> PermissionMode {
        self.tool_requirements
            .get(tool_name)
            .copied()
            .unwrap_or(PermissionMode::DangerFullAccess)
    }

    #[must_use]
    pub fn authorize(
        &self,
        tool_name: &str,
        input: &str,
        prompter: Option<&mut dyn PermissionPrompter>,
    ) -> PermissionOutcome {
        self.authorize_with_context(tool_name, input, &PermissionContext::default(), prompter)
    }

    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn authorize_with_context(
        &self,
        tool_name: &str,
        input: &str,
        context: &PermissionContext,
        prompter: Option<&mut dyn PermissionPrompter>,
    ) -> PermissionOutcome {
        if let Some(rule) = Self::find_matching_rule(&self.deny_rules, tool_name, input) {
            return PermissionOutcome::Deny {
                reason: format!(
                    "Permission to use {tool_name} has been denied by rule '{}'",
                    rule.raw
                ),
            };
        }

        let current_mode = self.active_mode();
        let required_mode = self.required_mode_for(tool_name);
        let ask_rule = Self::find_matching_rule(&self.ask_rules, tool_name, input);
        let allow_rule = Self::find_matching_rule(&self.allow_rules, tool_name, input);

        match context.override_decision() {
            Some(PermissionOverride::Deny) => {
                return PermissionOutcome::Deny {
                    reason: context.override_reason().map_or_else(
                        || format!("tool '{tool_name}' denied by hook"),
                        ToOwned::to_owned,
                    ),
                };
            }
            Some(PermissionOverride::Ask) => {
                let reason = context.override_reason().map_or_else(
                    || format!("tool '{tool_name}' requires approval due to hook guidance"),
                    ToOwned::to_owned,
                );
                return Self::prompt_or_deny(
                    tool_name,
                    input,
                    current_mode,
                    required_mode,
                    Some(reason),
                    prompter,
                );
            }
            Some(PermissionOverride::Allow) => {
                if let Some(rule) = ask_rule {
                    let reason = format!(
                        "tool '{tool_name}' requires approval due to ask rule '{}'",
                        rule.raw
                    );
                    return Self::prompt_or_deny(
                        tool_name,
                        input,
                        current_mode,
                        required_mode,
                        Some(reason),
                        prompter,
                    );
                }
                if allow_rule.is_some()
                    || current_mode == PermissionMode::Allow
                    || current_mode >= required_mode
                {
                    return PermissionOutcome::Allow;
                }
            }
            None => {}
        }

        if let Some(rule) = ask_rule {
            let reason = format!(
                "tool '{tool_name}' requires approval due to ask rule '{}'",
                rule.raw
            );
            return Self::prompt_or_deny(
                tool_name,
                input,
                current_mode,
                required_mode,
                Some(reason),
                prompter,
            );
        }

        if allow_rule.is_some()
            || current_mode == PermissionMode::Allow
            || current_mode >= required_mode
        {
            return PermissionOutcome::Allow;
        }

        if current_mode == PermissionMode::Prompt
            || (current_mode == PermissionMode::WorkspaceWrite
                && required_mode == PermissionMode::DangerFullAccess)
        {
            let reason = Some(format!(
                "tool '{tool_name}' requires approval to escalate from {} to {}",
                current_mode.as_str(),
                required_mode.as_str()
            ));
            return Self::prompt_or_deny(
                tool_name,
                input,
                current_mode,
                required_mode,
                reason,
                prompter,
            );
        }

        PermissionOutcome::Deny {
            reason: format!(
                "tool '{tool_name}' requires {} permission; current mode is {}",
                required_mode.as_str(),
                current_mode.as_str()
            ),
        }
    }

    fn prompt_or_deny(
        tool_name: &str,
        input: &str,
        current_mode: PermissionMode,
        required_mode: PermissionMode,
        reason: Option<String>,
        mut prompter: Option<&mut dyn PermissionPrompter>,
    ) -> PermissionOutcome {
        let request = PermissionRequest {
            tool_name: tool_name.to_string(),
            input: input.to_string(),
            current_mode,
            required_mode,
            reason: reason.clone(),
        };

        match prompter.as_mut() {
            Some(prompter) => match prompter.decide(&request) {
                PermissionPromptDecision::Allow => PermissionOutcome::Allow,
                PermissionPromptDecision::Deny { reason } => PermissionOutcome::Deny { reason },
            },
            None => PermissionOutcome::Deny {
                reason: reason.unwrap_or_else(|| {
                    format!(
                        "tool '{tool_name}' requires approval to run while mode is {}",
                        current_mode.as_str()
                    )
                }),
            },
        }
    }

    fn find_matching_rule<'a>(
        rules: &'a [PermissionRule],
        tool_name: &str,
        input: &str,
    ) -> Option<&'a PermissionRule> {
        rules.iter().find(|rule| rule.matches(tool_name, input))
    }

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PermissionRule {
    raw: String,
    tool_name: String,
    matcher: PermissionRuleMatcher,

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PermissionRuleMatcher {
    Any,
    Exact(String),
    Prefix(String),

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

impl PermissionRule {
    fn parse(raw: &str) -> Self {
        let trimmed = raw.trim();
        let open = find_first_unescaped(trimmed, '(');
        let close = find_last_unescaped(trimmed, ')');

        if let (Some(open), Some(close)) = (open, close) {
            if close == trimmed.len() - 1 && open < close {
                let tool_name = trimmed[..open].trim();
                let content = &trimmed[open + 1..close];
                if !tool_name.is_empty() {
                    let matcher = parse_rule_matcher(content);
                    return Self {
                        raw: trimmed.to_string(),
                        tool_name: tool_name.to_string(),
                        matcher,
                    };
                }
            }
        }

        Self {
            raw: trimmed.to_string(),
            tool_name: trimmed.to_string(),
            matcher: PermissionRuleMatcher::Any,
        }
    }

    fn matches(&self, tool_name: &str, input: &str) -> bool {
        if self.tool_name != tool_name {
            return false;
        }

        match &self.matcher {
            PermissionRuleMatcher::Any => true,
            PermissionRuleMatcher::Exact(expected) => {
                extract_permission_subject(input).is_some_and(|candidate| candidate == *expected)
            }
            PermissionRuleMatcher::Prefix(prefix) => extract_permission_subject(input)
                .is_some_and(|candidate| candidate.starts_with(prefix)),
        }
    }

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

fn parse_rule_matcher(content: &str) -> PermissionRuleMatcher {
    let unescaped = unescape_rule_content(content.trim());
    if unescaped.is_empty() || unescaped == "*" {
        PermissionRuleMatcher::Any
    } else if let Some(prefix) = unescaped.strip_suffix(":*") {
        PermissionRuleMatcher::Prefix(prefix.to_string())
    } else {
        PermissionRuleMatcher::Exact(unescaped)
    }

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

fn unescape_rule_content(content: &str) -> String {
    content
        .replace(r"\(", "(")
        .replace(r"\)", ")")
        .replace(r"\\", r"\")

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

fn find_first_unescaped(value: &str, needle: char) -> Option<usize> {
    let mut escaped = false;
    for (idx, ch) in value.char_indices() {
        if ch == '\\' {
            escaped = !escaped;
            continue;
        }
        if ch == needle && !escaped {
            return Some(idx);
        }
        escaped = false;
    }
    None

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

fn find_last_unescaped(value: &str, needle: char) -> Option<usize> {
    let chars = value.char_indices().collect::<Vec<_>>();
    for (pos, (idx, ch)) in chars.iter().enumerate().rev() {
        if *ch != needle {
            continue;
        }
        let mut backslashes = 0;
        for (_, prev) in chars[..pos].iter().rev() {
            if *prev == '\\' {
                backslashes += 1;
            } else {
                break;
            }
        }
        if backslashes % 2 == 0 {
            return Some(*idx);
        }
    }
    None

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

fn extract_permission_subject(input: &str) -> Option<String> {
    let parsed = serde_json::from_str::<Value>(input).ok();
    if let Some(Value::Object(object)) = parsed {
        for key in [
            "command",
            "path",
            "file_path",
            "filePath",
            "notebook_path",
            "notebookPath",
            "url",
            "pattern",
            "code",
            "message",
        ] {
            if let Some(value) = object.get(key).and_then(Value::as_str) {
                return Some(value.to_string());
            }
        }
    }

    (!input.trim().is_empty()).then(|| input.to_string())

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalDelegationHop, ApprovalScope, ApprovalTokenError, ApprovalTokenGrant,
        ApprovalTokenLedger, ApprovalTokenStatus, PermissionContext, PermissionMode,
        PermissionOutcome, PermissionOverride, PermissionPolicy, PermissionPromptDecision,
        PermissionPrompter, PermissionRequest,
    };
    use crate::config::RuntimePermissionRuleConfig;

    struct RecordingPrompter {
        seen: Vec<PermissionRequest>,
        allow: bool,
    }

    impl PermissionPrompter for RecordingPrompter {
        fn decide(&mut self, request: &PermissionRequest) -> PermissionPromptDecision {
            self.seen.push(request.clone());
            if self.allow {
                PermissionPromptDecision::Allow
            } else {
                PermissionPromptDecision::Deny {
                    reason: "not now".to_string(),
                }
            }
        }
    }

    #[test]
    fn allows_tools_when_active_mode_meets_requirement() {
        let policy = PermissionPolicy::new(PermissionMode::WorkspaceWrite)
            .with_tool_requirement("read_file", PermissionMode::ReadOnly)
            .with_tool_requirement("write_file", PermissionMode::WorkspaceWrite);

        assert_eq!(
            policy.authorize("read_file", "{}", None),
            PermissionOutcome::Allow
        );
        assert_eq!(
            policy.authorize("write_file", "{}", None),
            PermissionOutcome::Allow
        );
    }

    #[test]
    fn denies_read_only_escalations_without_prompt() {
        let policy = PermissionPolicy::new(PermissionMode::ReadOnly)
            .with_tool_requirement("write_file", PermissionMode::WorkspaceWrite)
            .with_tool_requirement("bash", PermissionMode::DangerFullAccess);

        assert!(matches!(
            policy.authorize("write_file", "{}", None),
            PermissionOutcome::Deny { reason } if reason.contains("requires workspace-write permission")
        ));
        assert!(matches!(
            policy.authorize("bash", "{}", None),
            PermissionOutcome::Deny { reason } if reason.contains("requires danger-full-access permission")
        ));
    }

    #[test]
    fn prompts_for_workspace_write_to_danger_full_access_escalation() {
        let policy = PermissionPolicy::new(PermissionMode::WorkspaceWrite)
            .with_tool_requirement("bash", PermissionMode::DangerFullAccess);
        let mut prompter = RecordingPrompter {
            seen: Vec::new(),
            allow: true,
        };

        let outcome = policy.authorize("bash", "echo hi", Some(&mut prompter));

        assert_eq!(outcome, PermissionOutcome::Allow);
        assert_eq!(prompter.seen.len(), 1);
        assert_eq!(prompter.seen[0].tool_name, "bash");
        assert_eq!(
            prompter.seen[0].current_mode,
            PermissionMode::WorkspaceWrite
        );
        assert_eq!(
            prompter.seen[0].required_mode,
            PermissionMode::DangerFullAccess
        );
    }

    #[test]
    fn honors_prompt_rejection_reason() {
        let policy = PermissionPolicy::new(PermissionMode::WorkspaceWrite)
            .with_tool_requirement("bash", PermissionMode::DangerFullAccess);
        let mut prompter = RecordingPrompter {
            seen: Vec::new(),
            allow: false,
        };

        assert!(matches!(
            policy.authorize("bash", "echo hi", Some(&mut prompter)),
            PermissionOutcome::Deny { reason } if reason == "not now"
        ));
    }

    #[test]
    fn applies_rule_based_denials_and_allows() {
        let rules = RuntimePermissionRuleConfig::new(
            vec!["bash(git:*)".to_string()],
            vec!["bash(rm -rf:*)".to_string()],
            Vec::new(),
        );
        let policy = PermissionPolicy::new(PermissionMode::ReadOnly)
            .with_tool_requirement("bash", PermissionMode::DangerFullAccess)
            .with_permission_rules(&rules);

        assert_eq!(
            policy.authorize("bash", r#"{"command":"git status"}"#, None),
            PermissionOutcome::Allow
        );
        assert!(matches!(
            policy.authorize("bash", r#"{"command":"rm -rf /tmp/x"}"#, None),
            PermissionOutcome::Deny { reason } if reason.contains("denied by rule")
        ));
    }

    #[test]
    fn ask_rules_force_prompt_even_when_mode_allows() {
        let rules = RuntimePermissionRuleConfig::new(
            Vec::new(),
            Vec::new(),
            vec!["bash(git:*)".to_string()],
        );
        let policy = PermissionPolicy::new(PermissionMode::DangerFullAccess)
            .with_tool_requirement("bash", PermissionMode::DangerFullAccess)
            .with_permission_rules(&rules);
        let mut prompter = RecordingPrompter {
            seen: Vec::new(),
            allow: true,
        };

        let outcome = policy.authorize("bash", r#"{"command":"git status"}"#, Some(&mut prompter));

        assert_eq!(outcome, PermissionOutcome::Allow);
        assert_eq!(prompter.seen.len(), 1);
        assert!(prompter.seen[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("ask rule")));
    }

    #[test]
    fn hook_allow_still_respects_ask_rules() {
        let rules = RuntimePermissionRuleConfig::new(
            Vec::new(),
            Vec::new(),
            vec!["bash(git:*)".to_string()],
        );
        let policy = PermissionPolicy::new(PermissionMode::ReadOnly)
            .with_tool_requirement("bash", PermissionMode::DangerFullAccess)
            .with_permission_rules(&rules);
        let context = PermissionContext::new(
            Some(PermissionOverride::Allow),
            Some("hook approved".to_string()),
        );
        let mut prompter = RecordingPrompter {
            seen: Vec::new(),
            allow: true,
        };

        let outcome = policy.authorize_with_context(
            "bash",
            r#"{"command":"git status"}"#,
            &context,
            Some(&mut prompter),
        );

        assert_eq!(outcome, PermissionOutcome::Allow);
        assert_eq!(prompter.seen.len(), 1);
    }

    #[test]
    fn hook_deny_short_circuits_permission_flow() {
        let policy = PermissionPolicy::new(PermissionMode::DangerFullAccess)
            .with_tool_requirement("bash", PermissionMode::DangerFullAccess);
        let context = PermissionContext::new(
            Some(PermissionOverride::Deny),
            Some("blocked by hook".to_string()),
        );

        assert_eq!(
            policy.authorize_with_context("bash", "{}", &context, None),
            PermissionOutcome::Deny {
                reason: "blocked by hook".to_string(),
            }
        );
    }

    #[test]
    fn hook_ask_forces_prompt() {
        let policy = PermissionPolicy::new(PermissionMode::DangerFullAccess)
            .with_tool_requirement("bash", PermissionMode::DangerFullAccess);
        let context = PermissionContext::new(
            Some(PermissionOverride::Ask),
            Some("hook requested confirmation".to_string()),
        );
        let mut prompter = RecordingPrompter {
            seen: Vec::new(),
            allow: true,
        };

        let outcome = policy.authorize_with_context("bash", "{}", &context, Some(&mut prompter));

        assert_eq!(outcome, PermissionOutcome::Allow);
        assert_eq!(prompter.seen.len(), 1);
        assert_eq!(
            prompter.seen[0].reason.as_deref(),
            Some("hook requested confirmation")
        );
    }

    #[test]
    fn approval_token_blocks_until_owner_grants_policy_exception() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        ledger.insert(ApprovalTokenGrant::pending(
            "tok-pending",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));

        assert!(matches!(
            ledger.verify("tok-missing", &scope, "release-bot", 10),
            Err(ApprovalTokenError::NoApproval)
        ));
        assert!(matches!(
            ledger.verify("tok-pending", &scope, "release-bot", 10),
            Err(ApprovalTokenError::ApprovalPending)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-granted",
            scope.clone(),
            "repo-owner",
            "release-bot",
        ));
        let audit = ledger
            .verify("tok-granted", &scope, "release-bot", 10)
            .expect("owner approval should verify");

        assert_eq!(audit.status, ApprovalTokenStatus::Granted);
        assert_eq!(audit.approving_actor, "repo-owner");
        assert_eq!(audit.executing_actor, "release-bot");
        assert!(audit.delegated_execution);
    }

    #[test]
    fn approval_token_is_one_time_use_and_rejects_replay() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("release_requires_owner", "release publish")
            .with_repository("sisyphus/claw-code");
        ledger.insert(ApprovalTokenGrant::granted(
            "tok-once",
            scope.clone(),
            "owner",
            "release-bot",
        ));

        let first = ledger
            .consume("tok-once", &scope, "release-bot", 10)
            .expect("first use should consume token");
        assert_eq!(first.status, ApprovalTokenStatus::Consumed);
        assert_eq!(first.uses, 1);

        assert!(matches!(
            ledger.consume("tok-once", &scope, "release-bot", 11),
            Err(ApprovalTokenError::ApprovalAlreadyConsumed)
        ));
        assert_eq!(
            ledger.get("tok-once").map(|grant| grant.status),
            Some(ApprovalTokenStatus::Consumed)
        );
    }

    #[test]
    fn approval_token_rejects_scope_expansion_expiry_and_revocation() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("main");
        let dev_scope = ApprovalScope::new("main_push_forbidden", "git push")
            .with_repository("sisyphus/claw-code")
            .with_branch("dev");

        ledger.insert(
            ApprovalTokenGrant::granted("tok-expiring", scope.clone(), "owner", "bot")
                .expires_at(20),
        );

        assert!(matches!(
            ledger.verify("tok-expiring", &dev_scope, "bot", 10),
            Err(ApprovalTokenError::ScopeMismatch { .. })
        ));
        assert!(matches!(
            ledger.verify("tok-expiring", &scope, "bot", 21),
            Err(ApprovalTokenError::ApprovalExpired)
        ));

        ledger.insert(ApprovalTokenGrant::granted(
            "tok-revoked",
            scope.clone(),
            "owner",
            "bot",
        ));
        let revoked = ledger
            .revoke("tok-revoked")
            .expect("revocation should be audited");
        assert_eq!(revoked.status, ApprovalTokenStatus::Revoked);
        assert!(matches!(
            ledger.verify("tok-revoked", &scope, "bot", 10),
            Err(ApprovalTokenError::ApprovalRevoked)
        ));
    }

    #[test]
    fn approval_token_preserves_delegation_traceability() {
        let mut ledger = ApprovalTokenLedger::new();
        let scope = ApprovalScope::new("deploy_requires_owner", "deploy prod");
        ledger.insert(
            ApprovalTokenGrant::granted("tok-delegated", scope.clone(), "owner", "deploy-bot")
                .with_delegation_hop(
                    ApprovalDelegationHop::new("owner", "owner approval")
                        .with_session_id("session-owner"),
                )
                .with_delegation_hop(
                    ApprovalDelegationHop::new("lead-agent", "handoff to deploy bot")
                        .with_session_id("session-lead"),
                ),
        );

        assert!(matches!(
            ledger.verify("tok-delegated", &scope, "unexpected-bot", 10),
            Err(ApprovalTokenError::UnauthorizedDelegate { expected, actual })
                if expected == "deploy-bot" && actual == "unexpected-bot"
        ));

        let audit = ledger
            .consume("tok-delegated", &scope, "deploy-bot", 10)
            .expect("approved delegate should consume token");
        let actors = audit
            .delegation_chain
            .iter()
            .map(|hop| hop.actor.as_str())
            .collect::<Vec<_>>();

        assert!(audit.delegated_execution);
        assert_eq!(actors, vec!["owner", "lead-agent", "deploy-bot"]);
        assert_eq!(audit.delegation_chain[0].session_id.as_deref(), Some("session-owner"));
        assert_eq!(audit.delegation_chain[1].session_id.as_deref(), Some("session-lead"));
    }

}
