use pqvault::crypto::*;
use pqvault::models::*;
use pqvault::providers::*;
use pqvault::health::*;
use pqvault::audit::*;
use pqvault::env_gen::*;
use pqvault::smart::*;
use std::collections::HashMap;

// ============================================================================
// CRYPTO STRESS TESTS
// ============================================================================

mod crypto_tests {
    use super::*;

    #[test]
    fn test_empty_plaintext() {
        let kp = generate_keypair().unwrap();
        let x_pub = kp.x25519_public.as_bytes().to_vec();
        let payload = hybrid_encrypt(b"", &kp.pq_public, &x_pub).unwrap();
        let decrypted = hybrid_decrypt(&payload, &kp.pq_secret, &kp.x25519_private).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn test_single_byte_plaintext() {
        let kp = generate_keypair().unwrap();
        let x_pub = kp.x25519_public.as_bytes().to_vec();
        let payload = hybrid_encrypt(&[0x42], &kp.pq_public, &x_pub).unwrap();
        let decrypted = hybrid_decrypt(&payload, &kp.pq_secret, &kp.x25519_private).unwrap();
        assert_eq!(decrypted, vec![0x42]);
    }

    #[test]
    fn test_large_plaintext_1mb() {
        let kp = generate_keypair().unwrap();
        let x_pub = kp.x25519_public.as_bytes().to_vec();
        let data = vec![0xAB; 1024 * 1024]; // 1 MB
        let payload = hybrid_encrypt(&data, &kp.pq_public, &x_pub).unwrap();
        let decrypted = hybrid_decrypt(&payload, &kp.pq_secret, &kp.x25519_private).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_binary_plaintext_all_bytes() {
        let kp = generate_keypair().unwrap();
        let x_pub = kp.x25519_public.as_bytes().to_vec();
        let data: Vec<u8> = (0..=255).collect(); // all 256 byte values
        let payload = hybrid_encrypt(&data, &kp.pq_public, &x_pub).unwrap();
        let decrypted = hybrid_decrypt(&payload, &kp.pq_secret, &kp.x25519_private).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_null_bytes_in_plaintext() {
        let kp = generate_keypair().unwrap();
        let x_pub = kp.x25519_public.as_bytes().to_vec();
        let data = b"\x00\x00\x00null\x00bytes\x00";
        let payload = hybrid_encrypt(data, &kp.pq_public, &x_pub).unwrap();
        let decrypted = hybrid_decrypt(&payload, &kp.pq_secret, &kp.x25519_private).unwrap();
        assert_eq!(decrypted, data.to_vec());
    }

    #[test]
    fn test_unicode_plaintext() {
        let kp = generate_keypair().unwrap();
        let x_pub = kp.x25519_public.as_bytes().to_vec();
        let data = "Hello 🌍 Привет мир 你好世界 🔐🔑".as_bytes();
        let payload = hybrid_encrypt(data, &kp.pq_public, &x_pub).unwrap();
        let decrypted = hybrid_decrypt(&payload, &kp.pq_secret, &kp.x25519_private).unwrap();
        assert_eq!(decrypted, data.to_vec());
        assert_eq!(
            String::from_utf8(decrypted).unwrap(),
            "Hello 🌍 Привет мир 你好世界 🔐🔑"
        );
    }

    #[test]
    fn test_decrypt_with_wrong_pq_key() {
        let kp1 = generate_keypair().unwrap();
        let kp2 = generate_keypair().unwrap();
        let x_pub = kp1.x25519_public.as_bytes().to_vec();
        let payload = hybrid_encrypt(b"secret", &kp1.pq_public, &x_pub).unwrap();
        // Use kp2's PQ secret (wrong) with kp1's X25519 private
        let result = hybrid_decrypt(&payload, &kp2.pq_secret, &kp1.x25519_private);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_x25519_key() {
        let kp1 = generate_keypair().unwrap();
        let kp2 = generate_keypair().unwrap();
        let x_pub = kp1.x25519_public.as_bytes().to_vec();
        let payload = hybrid_encrypt(b"secret", &kp1.pq_public, &x_pub).unwrap();
        // Use kp1's PQ secret (correct) with kp2's X25519 private (wrong)
        let result = hybrid_decrypt(&payload, &kp1.pq_secret, &kp2.x25519_private);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_both_wrong_keys() {
        let kp1 = generate_keypair().unwrap();
        let kp2 = generate_keypair().unwrap();
        let x_pub = kp1.x25519_public.as_bytes().to_vec();
        let payload = hybrid_encrypt(b"secret", &kp1.pq_public, &x_pub).unwrap();
        let result = hybrid_decrypt(&payload, &kp2.pq_secret, &kp2.x25519_private);
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_ciphertext() {
        let kp = generate_keypair().unwrap();
        let x_pub = kp.x25519_public.as_bytes().to_vec();
        let mut payload = hybrid_encrypt(b"secret", &kp.pq_public, &x_pub).unwrap();
        // Flip a bit in ciphertext
        if let Some(byte) = payload.ciphertext.last_mut() {
            *byte ^= 0xFF;
        }
        let result = hybrid_decrypt(&payload, &kp.pq_secret, &kp.x25519_private);
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_nonce() {
        let kp = generate_keypair().unwrap();
        let x_pub = kp.x25519_public.as_bytes().to_vec();
        let mut payload = hybrid_encrypt(b"secret", &kp.pq_public, &x_pub).unwrap();
        payload.nonce[0] ^= 0xFF;
        let result = hybrid_decrypt(&payload, &kp.pq_secret, &kp.x25519_private);
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_salt() {
        let kp = generate_keypair().unwrap();
        let x_pub = kp.x25519_public.as_bytes().to_vec();
        let mut payload = hybrid_encrypt(b"secret", &kp.pq_public, &x_pub).unwrap();
        payload.salt[0] ^= 0xFF;
        let result = hybrid_decrypt(&payload, &kp.pq_secret, &kp.x25519_private);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_serialized_payload() {
        let kp = generate_keypair().unwrap();
        let x_pub = kp.x25519_public.as_bytes().to_vec();
        let payload = hybrid_encrypt(b"secret", &kp.pq_public, &x_pub).unwrap();
        let serialized = payload.serialize();

        // Too short for header
        assert!(EncryptedPayload::deserialize(&serialized[..10]).is_err());

        // Header present but body truncated
        assert!(EncryptedPayload::deserialize(&serialized[..25]).is_err());

        // Missing last byte
        assert!(EncryptedPayload::deserialize(&serialized[..serialized.len() - 1]).is_err());
    }

    #[test]
    fn test_empty_serialized_payload() {
        assert!(EncryptedPayload::deserialize(&[]).is_err());
    }

    #[test]
    fn test_garbage_serialized_payload() {
        assert!(EncryptedPayload::deserialize(&[0xFF; 100]).is_err());
    }

    #[test]
    fn test_serialized_payload_with_overflow_lengths() {
        // Header claiming impossibly large lengths
        let mut data = vec![0u8; 20];
        // Set first length to u32::MAX
        data[0..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(EncryptedPayload::deserialize(&data).is_err());
    }

    #[test]
    fn test_each_encryption_is_unique() {
        let kp = generate_keypair().unwrap();
        let x_pub = kp.x25519_public.as_bytes().to_vec();
        let p1 = hybrid_encrypt(b"same", &kp.pq_public, &x_pub).unwrap();
        let p2 = hybrid_encrypt(b"same", &kp.pq_public, &x_pub).unwrap();
        // Same plaintext, different ciphertext (due to random nonce + ephemeral keys)
        assert_ne!(p1.ciphertext, p2.ciphertext);
        assert_ne!(p1.nonce, p2.nonce);
        assert_ne!(p1.pq_ciphertext, p2.pq_ciphertext);
        assert_ne!(p1.x25519_ephemeral, p2.x25519_ephemeral);
    }

    #[test]
    fn test_multiple_keypairs_independent() {
        let kp1 = generate_keypair().unwrap();
        let kp2 = generate_keypair().unwrap();
        assert_ne!(kp1.pq_public, kp2.pq_public);
        assert_ne!(kp1.pq_secret, kp2.pq_secret);
        assert_ne!(
            kp1.x25519_public.as_bytes(),
            kp2.x25519_public.as_bytes()
        );
    }

    #[test]
    fn test_encrypt_with_wrong_size_pq_key() {
        let kp = generate_keypair().unwrap();
        let x_pub = kp.x25519_public.as_bytes().to_vec();
        // PQ key too short
        let result = hybrid_encrypt(b"secret", &[0u8; 10], &x_pub);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_with_wrong_size_x25519_key() {
        let kp = generate_keypair().unwrap();
        // X25519 key too short
        let result = hybrid_encrypt(b"secret", &kp.pq_public, &[0u8; 10]);
        assert!(result.is_err());
    }

    // Password encryption stress tests

    #[test]
    fn test_password_empty_plaintext() {
        let enc = password_encrypt(b"", "password").unwrap();
        let dec = password_decrypt(&enc, "password").unwrap();
        assert_eq!(dec, b"");
    }

    #[test]
    fn test_password_empty_password() {
        let enc = password_encrypt(b"data", "").unwrap();
        let dec = password_decrypt(&enc, "").unwrap();
        assert_eq!(dec, b"data");
    }

    #[test]
    fn test_password_unicode_password() {
        let pw = "пароль🔐密码";
        let enc = password_encrypt(b"secret", pw).unwrap();
        let dec = password_decrypt(&enc, pw).unwrap();
        assert_eq!(dec, b"secret");
    }

    #[test]
    fn test_password_very_long_password() {
        let pw = "a".repeat(10_000);
        let enc = password_encrypt(b"secret", &pw).unwrap();
        let dec = password_decrypt(&enc, &pw).unwrap();
        assert_eq!(dec, b"secret");
    }

    #[test]
    fn test_password_special_chars() {
        let pw = "p@$$w0rd!#%^&*()_+-=[]{}|;':\",./<>?`~";
        let enc = password_encrypt(b"data", pw).unwrap();
        let dec = password_decrypt(&enc, pw).unwrap();
        assert_eq!(dec, b"data");
    }

    #[test]
    fn test_password_decrypt_truncated() {
        let enc = password_encrypt(b"data", "pw").unwrap();
        // Too short to have salt + nonce
        assert!(password_decrypt(&enc[..10], "pw").is_err());
        // Has salt + nonce but truncated ciphertext
        assert!(password_decrypt(&enc[..44], "pw").is_err());
    }

    #[test]
    fn test_password_decrypt_corrupted() {
        let mut enc = password_encrypt(b"data", "pw").unwrap();
        // Corrupt the ciphertext (after salt + nonce = 44 bytes)
        if enc.len() > 45 {
            enc[45] ^= 0xFF;
        }
        assert!(password_decrypt(&enc, "pw").is_err());
    }

    #[test]
    fn test_password_decrypt_empty_input() {
        assert!(password_decrypt(&[], "pw").is_err());
    }

    #[test]
    fn test_password_each_encryption_unique() {
        let e1 = password_encrypt(b"same", "pw").unwrap();
        let e2 = password_encrypt(b"same", "pw").unwrap();
        assert_ne!(e1, e2); // Different salt + nonce
    }
}

// ============================================================================
// MODELS STRESS TESTS
// ============================================================================

mod models_tests {
    use super::*;

    #[test]
    fn test_auto_categorize_exact_matches() {
        assert_eq!(auto_categorize("ANTHROPIC_API_KEY"), "ai");
        assert_eq!(auto_categorize("OPENAI_KEY"), "ai");
        assert_eq!(auto_categorize("STRIPE_SECRET"), "payment");
        assert_eq!(auto_categorize("AWS_ACCESS_KEY"), "cloud");
        assert_eq!(auto_categorize("TWITTER_TOKEN"), "social");
        assert_eq!(auto_categorize("RESEND_API_KEY"), "email");
        assert_eq!(auto_categorize("SUPABASE_URL"), "database");
        assert_eq!(auto_categorize("SESSION_SECRET"), "auth");
        assert_eq!(auto_categorize("SERPER_API_KEY"), "search");
    }

    #[test]
    fn test_auto_categorize_no_false_positives() {
        // "AWS" should NOT match inside "AWESOME"
        assert_eq!(auto_categorize("MY_AWESOME_VAR"), "general");
        // "DB_" should match as word boundary (DB_ is a database pattern)
        assert_eq!(auto_categorize("DB_HOST"), "database");
        // Random key
        assert_eq!(auto_categorize("RANDOM_THING"), "general");
        // "HF" inside another word should not match
        assert_eq!(auto_categorize("SHUFFLE_MODE"), "general");
    }

    #[test]
    fn test_auto_categorize_case_insensitive() {
        assert_eq!(auto_categorize("anthropic_api_key"), "ai");
        assert_eq!(auto_categorize("Stripe_Key"), "payment");
    }

    #[test]
    fn test_auto_categorize_empty() {
        assert_eq!(auto_categorize(""), "general");
    }

    #[test]
    fn test_auto_categorize_special_chars() {
        // Hyphens are word separators, so ANTHROPIC is matched
        assert_eq!(auto_categorize("ANTHROPIC-API-KEY"), "ai");
        assert_eq!(auto_categorize("ANTHROPIC_API_KEY"), "ai");
    }

    #[test]
    fn test_secret_entry_defaults() {
        let json = r#"{"value": "test"}"#;
        let entry: SecretEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.value, "test");
        assert_eq!(entry.category, "general");
        assert!(entry.description.is_empty());
        assert_eq!(entry.rotation_days, 90);
        assert!(entry.expires.is_none());
        assert!(entry.projects.is_empty());
        assert!(entry.tags.is_empty());
    }

    #[test]
    fn test_vault_data_default() {
        let vault = VaultData::default();
        assert_eq!(vault.version, "1.0");
        assert!(vault.secrets.is_empty());
        assert!(vault.projects.is_empty());
    }

    #[test]
    fn test_secret_entry_roundtrip_json() {
        let entry = SecretEntry {
            value: "sk-ant-xxx".to_string(),
            category: "ai".to_string(),
            description: "Test key with \"quotes\" and \nnewlines".to_string(),
            created: "2025-01-01".to_string(),
            rotated: "2025-01-01".to_string(),
            expires: Some("2026-01-01".to_string()),
            rotation_days: 30,
            projects: vec!["proj1".to_string(), "proj2".to_string()],
            tags: vec!["production".to_string(), "critical".to_string()],
            account: None,
            environment: None,
            related_keys: vec![],
            last_verified: None,
            last_error: None,
            key_status: "unknown".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: SecretEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.value, entry.value);
        assert_eq!(decoded.description, entry.description);
        assert_eq!(decoded.projects, entry.projects);
        assert_eq!(decoded.tags, entry.tags);
    }

    #[test]
    fn test_vault_data_many_secrets() {
        let mut vault = VaultData::default();
        for i in 0..1000 {
            vault.secrets.insert(
                format!("KEY_{}", i),
                SecretEntry {
                    value: format!("value_{}", i),
                    category: "general".to_string(),
                    description: String::new(),
                    created: "2025-01-01".to_string(),
                    rotated: "2025-01-01".to_string(),
                    expires: None,
                    rotation_days: 90,
                    projects: vec![],
                    tags: vec![],
                    account: None,
                    environment: None,
                    related_keys: vec![],
                    last_verified: None,
                    last_error: None,
                    key_status: "unknown".to_string(),
                },
            );
        }
        let json = serde_json::to_string(&vault).unwrap();
        let decoded: VaultData = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.secrets.len(), 1000);
    }

    #[test]
    fn test_secret_entry_unicode_value() {
        let entry = SecretEntry {
            value: "Пароль🔐密码".to_string(),
            category: "general".to_string(),
            description: "Unicode test 🌍".to_string(),
            created: "2025-01-01".to_string(),
            rotated: "2025-01-01".to_string(),
            expires: None,
            rotation_days: 90,
            projects: vec![],
            tags: vec!["тег".to_string()],
            account: None,
            environment: None,
            related_keys: vec![],
            last_verified: None,
            last_error: None,
            key_status: "unknown".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: SecretEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.value, "Пароль🔐密码");
        assert_eq!(decoded.tags[0], "тег");
    }

    #[test]
    fn test_category_patterns_complete() {
        let patterns = category_patterns();
        let categories: Vec<&str> = patterns.iter().map(|(c, _)| *c).collect();
        assert!(categories.contains(&"ai"));
        assert!(categories.contains(&"payment"));
        assert!(categories.contains(&"cloud"));
        assert!(categories.contains(&"social"));
        assert!(categories.contains(&"email"));
        assert!(categories.contains(&"database"));
        assert!(categories.contains(&"auth"));
        assert!(categories.contains(&"search"));
    }
}

// ============================================================================
// PROVIDER STRESS TESTS
// ============================================================================

mod provider_tests {
    use super::*;

    #[test]
    fn test_detect_provider_by_name() {
        assert_eq!(detect_provider("ANTHROPIC_API_KEY", ""), Some("anthropic".into()));
        assert_eq!(detect_provider("OPENAI_KEY", ""), Some("openai".into()));
        assert_eq!(detect_provider("GITHUB_TOKEN", ""), Some("github".into()));
        assert_eq!(detect_provider("STRIPE_KEY", ""), Some("stripe".into()));
        assert_eq!(detect_provider("RESEND_API_KEY", ""), Some("resend".into()));
        assert_eq!(detect_provider("ELEVENLABS_KEY", ""), Some("elevenlabs".into()));
        assert_eq!(detect_provider("SERPER_API_KEY", ""), Some("serper".into()));
    }

    #[test]
    fn test_detect_provider_by_value_pattern() {
        assert_eq!(detect_provider("MY_KEY", "sk-ant-test123"), Some("anthropic".into()));
        assert_eq!(detect_provider("MY_KEY", "ghp_1234567890abcdefghij"), Some("github".into()));
        assert_eq!(detect_provider("MY_KEY", "sk_live_test1234567890"), Some("stripe".into()));
        assert_eq!(detect_provider("MY_KEY", "sk_test_test1234567890"), Some("stripe".into()));
        assert_eq!(detect_provider("MY_KEY", "re_test123"), Some("resend".into()));
        assert_eq!(detect_provider("MY_KEY", "AIzaSomethinghere"), Some("google".into()));
        assert_eq!(
            detect_provider("MY_KEY", "BSAtesttesttesttesttesttesttest"),
            Some("brave".into())
        );
    }

    #[test]
    fn test_detect_provider_unknown() {
        assert_eq!(detect_provider("RANDOM_VAR", "some_value"), None);
        assert_eq!(detect_provider("", ""), None);
    }

    #[test]
    fn test_detect_provider_no_false_positive_on_name() {
        // "CLOUDFLARE" should match but "CLOUD" alone shouldn't match cloudflare
        // (it would match "cloud" category in auto_categorize, but not in detect_provider)
        assert_eq!(detect_provider("MY_CLOUD_VAR", ""), None);
        assert_eq!(detect_provider("CLOUDFLARE_TOKEN", ""), Some("cloudflare".into()));
        assert_eq!(detect_provider("CF_API_TOKEN", ""), Some("cloudflare".into()));
    }

    #[test]
    fn test_detect_provider_case_insensitive_name() {
        assert_eq!(detect_provider("anthropic_key", ""), Some("anthropic".into()));
        assert_eq!(detect_provider("Openai_Token", ""), Some("openai".into()));
    }

    #[test]
    fn test_get_provider_returns_config() {
        let p = get_provider("anthropic").unwrap();
        assert_eq!(p.display_name, "Anthropic");
        assert_eq!(p.requests_per_minute, Some(50));
        assert_eq!(p.rotation_days, 90);
    }

    #[test]
    fn test_get_provider_unknown() {
        assert!(get_provider("nonexistent").is_none());
        assert!(get_provider("").is_none());
    }

    #[test]
    fn test_all_providers_have_display_names() {
        for (_, config) in PROVIDERS.iter() {
            assert!(!config.display_name.is_empty());
        }
    }

    #[test]
    fn test_all_providers_have_positive_rotation_days() {
        for (_, config) in PROVIDERS.iter() {
            assert!(config.rotation_days > 0);
        }
    }

    #[test]
    fn test_provider_key_patterns_are_valid_regex() {
        for (name, config) in PROVIDERS.iter() {
            if let Some(ref pat) = config.key_pattern {
                assert!(
                    regex::Regex::new(pat).is_ok(),
                    "Invalid regex for provider {}: {}",
                    name,
                    pat
                );
            }
        }
    }
}

// ============================================================================
// HEALTH STRESS TESTS
// ============================================================================

mod health_tests {
    use super::*;

    fn make_secret(rotated: &str, rotation_days: i64, expires: Option<&str>, projects: Vec<&str>) -> SecretEntry {
        SecretEntry {
            value: "test".to_string(),
            category: "general".to_string(),
            description: String::new(),
            created: "2020-01-01".to_string(),
            rotated: rotated.to_string(),
            expires: expires.map(|s| s.to_string()),
            rotation_days,
            projects: projects.into_iter().map(|s| s.to_string()).collect(),
            tags: vec![],
            account: None,
            environment: None,
            related_keys: vec![],
            last_verified: None,
            last_error: None,
            key_status: "unknown".to_string(),
        }
    }

    #[test]
    fn test_empty_vault_is_healthy() {
        let vault = VaultData::default();
        let report = check_health(&vault);
        assert!(report.is_healthy());
        assert_eq!(report.total_secrets, 0);
        assert!(report.expired.is_empty());
        assert!(report.needs_rotation.is_empty());
        assert!(report.orphaned.is_empty());
    }

    #[test]
    fn test_fresh_key_is_healthy() {
        let mut vault = VaultData::default();
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        vault.secrets.insert("KEY".into(), make_secret(&today, 90, None, vec!["proj"]));
        let report = check_health(&vault);
        assert!(report.is_healthy());
        assert!(report.orphaned.is_empty());
    }

    #[test]
    fn test_expired_key_detected() {
        let mut vault = VaultData::default();
        vault.secrets.insert("KEY".into(), make_secret("2020-01-01", 90, Some("2020-06-01"), vec!["proj"]));
        let report = check_health(&vault);
        assert!(!report.is_healthy());
        assert!(report.expired.contains(&"KEY".to_string()));
    }

    #[test]
    fn test_rotation_due_detected() {
        let mut vault = VaultData::default();
        // Rotated 200 days ago, rotation_days = 90
        vault.secrets.insert("KEY".into(), make_secret("2020-01-01", 90, None, vec!["proj"]));
        let report = check_health(&vault);
        assert!(report.needs_rotation.contains(&"KEY".to_string()));
    }

    #[test]
    fn test_rotation_days_zero_skips_check() {
        let mut vault = VaultData::default();
        vault.secrets.insert("KEY".into(), make_secret("2020-01-01", 0, None, vec!["proj"]));
        let report = check_health(&vault);
        // Should NOT appear in needs_rotation
        assert!(!report.needs_rotation.contains(&"KEY".to_string()));
    }

    #[test]
    fn test_orphaned_key_detected() {
        let mut vault = VaultData::default();
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        vault.secrets.insert("ORPHAN".into(), make_secret(&today, 90, None, vec![]));
        let report = check_health(&vault);
        assert!(report.orphaned.contains(&"ORPHAN".to_string()));
    }

    #[test]
    fn test_categories_counted() {
        let mut vault = VaultData::default();
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        for i in 0..5 {
            let mut s = make_secret(&today, 90, None, vec!["proj"]);
            s.category = "ai".to_string();
            vault.secrets.insert(format!("AI_{}", i), s);
        }
        for i in 0..3 {
            let mut s = make_secret(&today, 90, None, vec!["proj"]);
            s.category = "payment".to_string();
            vault.secrets.insert(format!("PAY_{}", i), s);
        }
        let report = check_health(&vault);
        assert_eq!(report.total_secrets, 8);
        assert_eq!(*report.by_category.get("ai").unwrap(), 5);
        assert_eq!(*report.by_category.get("payment").unwrap(), 3);
    }

    #[test]
    fn test_invalid_date_skips_checks() {
        let mut vault = VaultData::default();
        vault.secrets.insert("KEY".into(), make_secret("not-a-date", 90, Some("also-not-a-date"), vec!["proj"]));
        let report = check_health(&vault);
        // Should not panic, should just skip these checks
        assert!(!report.expired.contains(&"KEY".to_string()));
        assert!(!report.needs_rotation.contains(&"KEY".to_string()));
    }

    #[test]
    fn test_expiry_today_is_expired() {
        let mut vault = VaultData::default();
        let today = chrono::Local::now().format("%Y-%m-%d").to_string();
        vault.secrets.insert("KEY".into(), make_secret(&today, 90, Some(&today), vec!["proj"]));
        let report = check_health(&vault);
        assert!(report.expired.contains(&"KEY".to_string()));
    }

    #[test]
    fn test_many_secrets_performance() {
        let mut vault = VaultData::default();
        for i in 0..10_000 {
            vault.secrets.insert(
                format!("KEY_{}", i),
                make_secret("2020-01-01", 90, None, vec![]),
            );
        }
        let report = check_health(&vault);
        assert_eq!(report.total_secrets, 10_000);
        assert_eq!(report.needs_rotation.len(), 10_000);
        assert_eq!(report.orphaned.len(), 10_000);
    }
}

// ============================================================================
// ENV_GEN STRESS TESTS
// ============================================================================

mod env_gen_tests {
    use super::*;

    fn make_vault_with_project() -> VaultData {
        let mut vault = VaultData::default();
        vault.secrets.insert("API_KEY".into(), SecretEntry {
            value: "sk-test-123".to_string(),
            category: "ai".to_string(),
            description: String::new(),
            created: "2025-01-01".to_string(),
            rotated: "2025-01-01".to_string(),
            expires: None,
            rotation_days: 90,
            projects: vec!["myapp".to_string()],
            tags: vec![],
            account: None,
            environment: None,
            related_keys: vec![],
            last_verified: None,
            last_error: None,
            key_status: "unknown".to_string(),
        });
        vault.secrets.insert("DB_URL".into(), SecretEntry {
            value: "postgres://localhost/db".to_string(),
            category: "database".to_string(),
            description: String::new(),
            created: "2025-01-01".to_string(),
            rotated: "2025-01-01".to_string(),
            expires: None,
            rotation_days: 90,
            projects: vec!["myapp".to_string()],
            tags: vec![],
            account: None,
            environment: None,
            related_keys: vec![],
            last_verified: None,
            last_error: None,
            key_status: "unknown".to_string(),
        });
        vault.projects.insert("myapp".into(), ProjectEntry {
            path: "/Users/test/myapp".to_string(),
            keys: vec!["API_KEY".to_string(), "DB_URL".to_string()],
            env_file: ".env.local".to_string(),
            env_extras: HashMap::new(),
        });
        vault
    }

    #[test]
    fn test_generate_env_basic() {
        let vault = make_vault_with_project();
        let env = generate_env(&vault, "myapp").unwrap();
        assert!(env.contains("API_KEY=sk-test-123"));
        assert!(env.contains("DB_URL=postgres://localhost/db"));
        assert!(env.starts_with("# Generated by pqvault"));
    }

    #[test]
    fn test_generate_env_unknown_project() {
        let vault = make_vault_with_project();
        let result = generate_env(&vault, "nonexistent");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not registered"));
    }

    #[test]
    fn test_generate_env_with_extras() {
        let mut vault = make_vault_with_project();
        vault.projects.get_mut("myapp").unwrap().env_extras.insert(
            "PORT".to_string(),
            "3000".to_string(),
        );
        let env = generate_env(&vault, "myapp").unwrap();
        assert!(env.contains("PORT=3000"));
    }

    #[test]
    fn test_generate_env_keys_sorted() {
        let vault = make_vault_with_project();
        let env = generate_env(&vault, "myapp").unwrap();
        let lines: Vec<&str> = env.lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .collect();
        // API_KEY should come before DB_URL alphabetically
        let api_pos = lines.iter().position(|l| l.starts_with("API_KEY")).unwrap();
        let db_pos = lines.iter().position(|l| l.starts_with("DB_URL")).unwrap();
        assert!(api_pos < db_pos);
    }

    #[test]
    fn test_generate_env_missing_secret_skipped() {
        let mut vault = make_vault_with_project();
        vault.projects.get_mut("myapp").unwrap().keys.push("NONEXISTENT".to_string());
        let env = generate_env(&vault, "myapp").unwrap();
        // Should not crash, should just skip the missing key
        assert!(!env.contains("NONEXISTENT="));
    }

    #[test]
    fn test_generate_env_value_with_equals() {
        let mut vault = make_vault_with_project();
        vault.secrets.get_mut("API_KEY").unwrap().value = "key=with=equals".to_string();
        let env = generate_env(&vault, "myapp").unwrap();
        assert!(env.contains("API_KEY=key=with=equals"));
    }

    #[test]
    fn test_generate_env_empty_project() {
        let mut vault = VaultData::default();
        vault.projects.insert("empty".into(), ProjectEntry {
            path: "/tmp".to_string(),
            keys: vec![],
            env_file: ".env".to_string(),
            env_extras: HashMap::new(),
        });
        let env = generate_env(&vault, "empty").unwrap();
        // Should just have the header comment
        assert!(env.starts_with("# Generated"));
    }
}

// ============================================================================
// SMART TRACKER STRESS TESTS
// ============================================================================

mod smart_tests {
    use super::*;

    #[test]
    fn test_token_bucket_allows_within_limit() {
        let mut bucket = TokenBucket::from_rpm(60);
        let (allowed, _wait) = bucket.try_consume();
        assert!(allowed);
    }

    #[test]
    fn test_token_bucket_exhaustion() {
        let mut bucket = TokenBucket::from_rpm(2);
        // Consume all tokens
        bucket.try_consume();
        bucket.try_consume();
        let (allowed, wait) = bucket.try_consume();
        assert!(!allowed);
        assert!(wait > 0.0);
    }

    #[test]
    fn test_key_usage_defaults() {
        let usage = KeyUsage::default();
        assert_eq!(usage.total_requests, 0);
        assert_eq!(usage.requests_today(), 0);
        assert_eq!(usage.requests_this_month(), 0);
        assert!(usage.last_used.is_none());
        assert!(usage.first_used.is_none());
        assert_eq!(usage.estimated_cost_usd, 0.0);
        assert!(usage.alerts.is_empty());
        assert!(usage.recent_callers.is_empty());
    }

    #[test]
    fn test_usage_tracker_ensure_key() {
        let mut tracker = UsageTracker::new();
        tracker.ensure_key("ANTHROPIC_API_KEY", "sk-ant-test");
        let usage = tracker.get_usage("ANTHROPIC_API_KEY").unwrap();
        assert_eq!(usage.provider, "anthropic");
    }

    #[test]
    fn test_usage_tracker_record_access() {
        let unique = format!("TEST_KEY_{}", std::process::id());
        let mut tracker = UsageTracker::new();
        let before = tracker.get_usage(&unique).map(|u| u.total_requests).unwrap_or(0);
        tracker.ensure_key(&unique, "");
        tracker.record_access(&unique, "test-caller");
        let usage = tracker.get_usage(&unique).unwrap();
        assert_eq!(usage.total_requests, before + 1);
        assert!(usage.last_used.is_some());
        assert!(usage.first_used.is_some());
        assert!(usage.recent_callers.last().unwrap().caller == "test-caller");
    }

    #[test]
    fn test_usage_tracker_recent_callers_capped() {
        let unique = format!("CAP_KEY_{}", std::process::id());
        let mut tracker = UsageTracker::new();
        tracker.ensure_key(&unique, "");
        for i in 0..30 {
            tracker.record_access(&unique, &format!("caller-{}", i));
        }
        let usage = tracker.get_usage(&unique).unwrap();
        assert!(usage.recent_callers.len() <= 20); // capped at 20
        assert!(usage.total_requests >= 30);
    }

    #[test]
    fn test_rate_limit_unknown_key() {
        let mut tracker = UsageTracker::new();
        let result = tracker.check_rate_limit("nonexistent");
        assert!(result.allowed);
        assert_eq!(result.remaining, -1);
    }

    #[test]
    fn test_rate_limit_unknown_provider() {
        let mut tracker = UsageTracker::new();
        tracker.ensure_key("MY_KEY", "random-value");
        let result = tracker.check_rate_limit("MY_KEY");
        assert!(result.allowed);
    }

    #[test]
    fn test_generate_dashboard_empty() {
        let secrets = HashMap::new();
        let tracker = UsageTracker::new();
        let dashboard = generate_dashboard(&secrets, &tracker);
        assert!(dashboard.contains("PQVault Smart Dashboard"));
        assert!(dashboard.contains("Total Keys:** 0"));
        assert!(dashboard.contains("vault_add"));
    }

    #[test]
    fn test_generate_dashboard_with_secrets() {
        let mut secrets = HashMap::new();
        secrets.insert("KEY1".to_string(), SecretEntry {
            value: "val".to_string(),
            category: "ai".to_string(),
            description: String::new(),
            created: "2025-01-01".to_string(),
            rotated: chrono::Local::now().format("%Y-%m-%d").to_string(),
            expires: None,
            rotation_days: 90,
            projects: vec![],
            tags: vec![],
            account: None,
            environment: None,
            related_keys: vec![],
            last_verified: None,
            last_error: None,
            key_status: "unknown".to_string(),
        });
        let tracker = UsageTracker::new();
        let dashboard = generate_dashboard(&secrets, &tracker);
        assert!(dashboard.contains("KEY1"));
        assert!(dashboard.contains("ai"));
    }

    #[test]
    fn test_generate_key_status() {
        let secret = SecretEntry {
            value: "val".to_string(),
            category: "ai".to_string(),
            description: String::new(),
            created: "2025-01-01".to_string(),
            rotated: "2025-01-01".to_string(),
            expires: None,
            rotation_days: 90,
            projects: vec![],
            tags: vec![],
            account: None,
            environment: None,
            related_keys: vec![],
            last_verified: None,
            last_error: None,
            key_status: "unknown".to_string(),
        };
        let tracker = UsageTracker::new();
        let status = generate_key_status("MY_KEY", &secret, &tracker);
        assert!(status.contains("MY_KEY Status"));
        assert!(status.contains("ai"));
        assert!(status.contains("Total: 0"));
    }

    #[test]
    fn test_alert_deduplication() {
        let mut tracker = UsageTracker::new();
        tracker.ensure_key("KEY", "");
        // Call check_smart_alerts twice rapidly — should not create duplicate alerts
        tracker.check_smart_alerts("KEY", "2020-01-01", 90);
        tracker.check_smart_alerts("KEY", "2020-01-01", 90);
        let alerts = tracker.get_active_alerts();
        // Count rotation_due alerts for KEY
        let rotation_alerts: Vec<_> = alerts
            .iter()
            .filter(|(k, a)| k == "KEY" && a.alert_type == "rotation_due")
            .collect();
        assert_eq!(rotation_alerts.len(), 1); // deduplicated
    }
}

// ============================================================================
// AUDIT STRESS TESTS
// ============================================================================

mod audit_tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_read_log_empty() {
        let entries = read_log("", 100);
        // May or may not have entries from other tests — just ensure no panic
        let _ = entries;
    }

    #[test]
    fn test_read_log_with_filter() {
        // Log multiple entries to ensure at least one survives any rotation
        let unique_key = format!("AUDIT_FILTER_{}_{}", std::process::id(), chrono::Local::now().timestamp_millis());
        for _ in 0..3 {
            log_access("test_read", &unique_key, "test_proj", "test");
        }
        // Read all entries (no filter) first to verify the file is readable
        let all = read_log("", 100000);
        // Now filter
        let filtered = read_log(&unique_key, 100000);
        assert!(
            filtered.iter().any(|e| e.key == unique_key),
            "Expected to find key {} in audit log. All entries: {}, filtered: {}",
            unique_key,
            all.len(),
            filtered.len()
        );
    }

    #[test]
    fn test_read_log_limit() {
        for i in 0..5 {
            log_access("test_limit", &format!("LIMIT_KEY_{}", i), "", "test");
        }
        let entries = read_log("", 3);
        assert!(entries.len() <= 3);
    }

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry {
            ts: "2025-01-01T00:00:00+00:00".to_string(),
            action: "get".to_string(),
            key: "MY_KEY".to_string(),
            project: "proj".to_string(),
            agent: "mcp".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.action, "get");
        assert_eq!(decoded.key, "MY_KEY");
    }

    #[test]
    fn test_audit_entry_with_special_chars() {
        log_access("test", "KEY_WITH \"QUOTES\"", "proj with spaces", "agent\nnewline");
        // Should not panic or corrupt the log
    }
}

// ============================================================================
// SERIALIZATION STRESS TESTS
// ============================================================================

mod serialization_tests {
    use super::*;

    #[test]
    fn test_encrypted_payload_roundtrip_many_sizes() {
        let kp = generate_keypair().unwrap();
        let x_pub = kp.x25519_public.as_bytes().to_vec();

        for size in [0, 1, 15, 16, 31, 32, 255, 256, 1023, 1024, 4096, 65535] {
            let data = vec![0xAB; size];
            let payload = hybrid_encrypt(&data, &kp.pq_public, &x_pub).unwrap();
            let serialized = payload.serialize();
            let deserialized = EncryptedPayload::deserialize(&serialized).unwrap();
            let decrypted = hybrid_decrypt(&deserialized, &kp.pq_secret, &kp.x25519_private).unwrap();
            assert_eq!(decrypted, data, "Failed for size {}", size);
        }
    }

    #[test]
    fn test_vault_data_json_roundtrip_complex() {
        let mut vault = VaultData::default();

        // Add secrets with various edge cases
        vault.secrets.insert("EMPTY_VALUE".into(), SecretEntry {
            value: String::new(),
            category: "general".to_string(),
            description: String::new(),
            created: "2025-01-01".to_string(),
            rotated: "2025-01-01".to_string(),
            expires: None,
            rotation_days: 0,
            projects: vec![],
            tags: vec![],
            account: None,
            environment: None,
            related_keys: vec![],
            last_verified: None,
            last_error: None,
            key_status: "unknown".to_string(),
        });

        vault.secrets.insert("UNICODE_VALUE".into(), SecretEntry {
            value: "🔐密码Пароль".to_string(),
            category: "general".to_string(),
            description: "Description with\nnewlines\tand\ttabs".to_string(),
            created: "2025-01-01".to_string(),
            rotated: "2025-01-01".to_string(),
            expires: Some("2099-12-31".to_string()),
            rotation_days: 365,
            projects: vec!["proj-1".to_string(), "proj-2".to_string()],
            tags: vec!["tag1".to_string(), "tag2".to_string(), "tag3".to_string()],
            account: None,
            environment: None,
            related_keys: vec![],
            last_verified: None,
            last_error: None,
            key_status: "unknown".to_string(),
        });

        vault.secrets.insert("LONG_VALUE".into(), SecretEntry {
            value: "a".repeat(10_000),
            category: "general".to_string(),
            description: String::new(),
            created: "2025-01-01".to_string(),
            rotated: "2025-01-01".to_string(),
            expires: None,
            rotation_days: 90,
            projects: vec![],
            tags: vec![],
            account: None,
            environment: None,
            related_keys: vec![],
            last_verified: None,
            last_error: None,
            key_status: "unknown".to_string(),
        });

        let json = serde_json::to_string_pretty(&vault).unwrap();
        let decoded: VaultData = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.secrets.len(), 3);
        assert_eq!(decoded.secrets["EMPTY_VALUE"].value, "");
        assert_eq!(decoded.secrets["UNICODE_VALUE"].value, "🔐密码Пароль");
        assert_eq!(decoded.secrets["LONG_VALUE"].value.len(), 10_000);
    }

    #[test]
    fn test_full_encrypt_decrypt_vault_data() {
        let kp = generate_keypair().unwrap();
        let x_pub = kp.x25519_public.as_bytes().to_vec();

        let mut vault = VaultData::default();
        for i in 0..100 {
            vault.secrets.insert(
                format!("KEY_{}", i),
                SecretEntry {
                    value: format!("secret_value_{}", i),
                    category: "general".to_string(),
                    description: format!("Description for key {}", i),
                    created: "2025-01-01".to_string(),
                    rotated: "2025-01-01".to_string(),
                    expires: None,
                    rotation_days: 90,
                    projects: vec![format!("proj_{}", i % 5)],
                    tags: vec![format!("tag_{}", i % 3)],
                    account: None,
                    environment: None,
                    related_keys: vec![],
                    last_verified: None,
                    last_error: None,
                    key_status: "unknown".to_string(),
                },
            );
        }

        // Serialize vault to JSON, encrypt, serialize payload, deserialize, decrypt, parse
        let json = serde_json::to_string(&vault).unwrap();
        let payload = hybrid_encrypt(json.as_bytes(), &kp.pq_public, &x_pub).unwrap();
        let serialized = payload.serialize();
        let deserialized = EncryptedPayload::deserialize(&serialized).unwrap();
        let decrypted = hybrid_decrypt(&deserialized, &kp.pq_secret, &kp.x25519_private).unwrap();
        let decoded: VaultData = serde_json::from_slice(&decrypted).unwrap();

        assert_eq!(decoded.secrets.len(), 100);
        assert_eq!(decoded.secrets["KEY_0"].value, "secret_value_0");
        assert_eq!(decoded.secrets["KEY_99"].value, "secret_value_99");
    }
}
