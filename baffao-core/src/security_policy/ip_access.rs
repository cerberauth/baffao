//! IP-based access control for OAuth operations.
//!
//! This module provides IP-based access control for OAuth operations, allowing
//! for restricting or allowing access based on client IP addresses.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use cidr::IpCidr;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::{BaffaoError, BaffaoResult};

/// Action to take for an IP access rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpAccessAction {
    /// Allow access from the specified IP/range
    Allow,
    /// Deny access from the specified IP/range
    Deny,
    /// Allow access but log it for monitoring
    AllowAndLog,
    /// Allow access but require additional verification
    AllowWithVerification,
}

/// IP access rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAccessRule {
    /// CIDR notation of the IP range (e.g., "192.168.1.0/24")
    pub cidr: String,
    /// Action to take for IPs in this range
    pub action: IpAccessAction,
    /// Note about this rule
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// When this rule was created
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    /// When this rule expires (if temporary)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Priority of the rule (higher number means higher priority)
    #[serde(default)]
    pub priority: i32,
}

/// Result of an IP access check.
#[derive(Debug, Clone)]
pub struct IpAccessResult {
    /// Whether access is allowed
    pub allowed: bool,
    /// Action taken
    pub action: IpAccessAction,
    /// Rule that matched
    pub matching_rule: Option<IpAccessRule>,
    /// Whether additional verification is required
    pub requires_verification: bool,
}

/// Interface for IP access policy.
#[async_trait]
pub trait IpAccessPolicy: Send + Sync {
    /// Check if access from the given IP should be allowed.
    async fn check_access(&self, ip: &str, context: Option<&HashMap<String, String>>) -> BaffaoResult<IpAccessResult>;
    
    /// Add a rule to the policy.
    async fn add_rule(&self, rule: IpAccessRule) -> BaffaoResult<()>;
    
    /// Remove a rule by CIDR.
    async fn remove_rule(&self, cidr: &str) -> BaffaoResult<()>;
    
    /// Get all rules.
    async fn get_rules(&self) -> BaffaoResult<Vec<IpAccessRule>>;
    
    /// Clear expired rules.
    async fn clear_expired_rules(&self) -> BaffaoResult<usize>;
}

/// Standard implementation of IpAccessPolicy.
#[derive(Clone)]
pub struct StandardIpAccessPolicy {
    /// Rules for IP access control
    rules: Arc<RwLock<Vec<IpAccessRule>>>,
    /// Default action when no rules match
    default_action: IpAccessAction,
}

impl StandardIpAccessPolicy {
    /// Creates a new IP access policy with the given default action.
    pub fn new(default_action: IpAccessAction) -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            default_action,
        }
    }
    
    /// Creates a new IP access policy with the given rules and default action.
    pub fn with_rules(rules: Vec<IpAccessRule>, default_action: IpAccessAction) -> Self {
        Self {
            rules: Arc::new(RwLock::new(rules)),
            default_action,
        }
    }
}

#[async_trait]
impl IpAccessPolicy for StandardIpAccessPolicy {
    async fn check_access(&self, ip_str: &str, _context: Option<&HashMap<String, String>>) -> BaffaoResult<IpAccessResult> {
        // Parse the IP address
        let ip = IpAddr::from_str(ip_str)
            .map_err(|e| BaffaoError::ValidationError(format!("Invalid IP address: {}", e)))?;
            
        // Get rules
        let rules = self.rules.read().await;
        
        // Sort rules by priority (highest first)
        let mut sorted_rules = rules.clone();
        sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        // Check if any rules match
        for rule in &sorted_rules {
            // Skip expired rules
            if let Some(expires_at) = rule.expires_at {
                if expires_at < Utc::now() {
                    continue;
                }
            }
            
            // Parse the CIDR
            let cidr = IpCidr::from_str(&rule.cidr)
                .map_err(|e| BaffaoError::ValidationError(format!("Invalid CIDR: {}", e)))?;
                
            // Check if IP is in CIDR
            if cidr.contains(&ip) {
                return Ok(IpAccessResult {
                    allowed: matches!(rule.action, IpAccessAction::Allow | IpAccessAction::AllowAndLog | IpAccessAction::AllowWithVerification),
                    action: rule.action,
                    matching_rule: Some(rule.clone()),
                    requires_verification: matches!(rule.action, IpAccessAction::AllowWithVerification),
                });
            }
        }
        
        // No rules matched, use default action
        Ok(IpAccessResult {
            allowed: matches!(self.default_action, IpAccessAction::Allow | IpAccessAction::AllowAndLog),
            action: self.default_action,
            matching_rule: None,
            requires_verification: matches!(self.default_action, IpAccessAction::AllowWithVerification),
        })
    }
    
    async fn add_rule(&self, rule: IpAccessRule) -> BaffaoResult<()> {
        // Validate the CIDR
        IpCidr::from_str(&rule.cidr)
            .map_err(|e| BaffaoError::ValidationError(format!("Invalid CIDR: {}", e)))?;
            
        // Add the rule
        let mut rules = self.rules.write().await;
        
        // Check if rule with this CIDR already exists
        let existing_index = rules.iter().position(|r| r.cidr == rule.cidr);
        
        if let Some(index) = existing_index {
            // Replace existing rule
            rules[index] = rule;
        } else {
            // Add new rule
            rules.push(rule);
        }
        
        Ok(())
    }
    
    async fn remove_rule(&self, cidr: &str) -> BaffaoResult<()> {
        let mut rules = self.rules.write().await;
        
        // Find and remove the rule
        let initial_len = rules.len();
        rules.retain(|r| r.cidr != cidr);
        
        if rules.len() == initial_len {
            Err(BaffaoError::NotFound(format!("Rule with CIDR {} not found", cidr)))
        } else {
            Ok(())
        }
    }
    
    async fn get_rules(&self) -> BaffaoResult<Vec<IpAccessRule>> {
        let rules = self.rules.read().await;
        Ok(rules.clone())
    }
    
    async fn clear_expired_rules(&self) -> BaffaoResult<usize> {
        let mut rules = self.rules.write().await;
        
        let now = Utc::now();
        let initial_len = rules.len();
        
        // Remove expired rules
        rules.retain(|rule| {
            if let Some(expires_at) = rule.expires_at {
                expires_at > now
            } else {
                true
            }
        });
        
        Ok(initial_len - rules.len())
    }
}

/// IP access manager that can be used to check access for OAuth operations.
pub struct IpAccessManager {
    /// IP access policy
    policy: Arc<dyn IpAccessPolicy>,
}

impl IpAccessManager {
    /// Creates a new IP access manager with the given policy.
    pub fn new(policy: Arc<dyn IpAccessPolicy>) -> Self {
        Self { policy }
    }
    
    /// Checks if access from the given IP should be allowed.
    pub async fn check_access(&self, ip: &str) -> BaffaoResult<IpAccessResult> {
        self.policy.check_access(ip, None).await
    }
    
    /// Checks if access from the given IP should be allowed with context.
    pub async fn check_access_with_context(&self, ip: &str, context: HashMap<String, String>) -> BaffaoResult<IpAccessResult> {
        self.policy.check_access(ip, Some(&context)).await
    }
    
    /// Adds a rule to the policy.
    pub async fn add_rule(&self, rule: IpAccessRule) -> BaffaoResult<()> {
        self.policy.add_rule(rule).await
    }
    
    /// Removes a rule by CIDR.
    pub async fn remove_rule(&self, cidr: &str) -> BaffaoResult<()> {
        self.policy.remove_rule(cidr).await
    }
    
    /// Gets all rules.
    pub async fn get_rules(&self) -> BaffaoResult<Vec<IpAccessRule>> {
        self.policy.get_rules().await
    }
    
    /// Clears expired rules.
    pub async fn clear_expired_rules(&self) -> BaffaoResult<usize> {
        self.policy.clear_expired_rules().await
    }
}