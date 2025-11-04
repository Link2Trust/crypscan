use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::utils::report::Finding;

/// CycloneDX CBOM (Cryptography Bill of Materials) generator
/// Implements CycloneDX 1.7 specification for cryptographic asset inventory

/// Main CBOM document structure
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CbomDocument {
    /// BOM format identifier (must be "CycloneDX")
    pub bom_format: String,
    /// CycloneDX specification version
    pub spec_version: String,
    /// Document serial number (RFC 4122 URN format)
    pub serial_number: String,
    /// CBOM document version
    pub version: u32,
    /// Document metadata
    pub metadata: CbomMetadata,
    /// List of cryptographic components
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<CbomComponent>>,
    /// Dependencies between components
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<Vec<Dependency>>,
}

/// CBOM metadata
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CbomMetadata {
    /// Timestamp when CBOM was generated
    pub timestamp: DateTime<Utc>,
    /// Tools used to generate CBOM
    pub tools: ToolsMetadata,
}

/// Tools metadata structure
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ToolsMetadata {
    /// Components (not used in this implementation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<serde_json::Value>>,
    /// Services that generated the CBOM
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<ToolService>>,
}

/// Tool service information
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ToolService {
    /// Provider information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<Provider>,
    /// Tool name
    pub name: String,
    /// Tool version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Provider information
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Provider {
    /// Provider name
    pub name: String,
}

/// CBOM component representing cryptographic assets
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CbomComponent {
    /// Component type (must be "cryptographic-asset")
    #[serde(rename = "type")]
    pub component_type: String,
    /// Unique identifier (kebab-case)
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    /// Component name (algorithm name)
    pub name: String,
    /// Evidence of component usage
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
    /// Cryptographic properties
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_properties: Option<CryptoProperties>,
}

/// Evidence of component usage
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    /// Occurrences where the component was found
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurrences: Option<Vec<Occurrence>>,
}

/// Occurrence of a cryptographic component
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Occurrence {
    /// File location
    pub location: String,
    /// Line number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// Column offset
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    /// Additional context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Cryptographic properties of a component
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CryptoProperties {
    /// Type of cryptographic asset
    pub asset_type: String,
    /// Algorithm properties (single object, not array)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm_properties: Option<AlgorithmProperties>,
    /// OID (Object Identifier)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
}

/// Algorithm properties
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmProperties {
    /// Primitive type (e.g., "hash", "signature", "encryption")
    pub primitive: String,
    /// Parameter set identifier (e.g., key size "256", "2048")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_set_identifier: Option<String>,
    /// Cryptographic functions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_functions: Option<Vec<String>>,
}

/// Dependency relationship
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    /// Reference to the component
    #[serde(rename = "ref")]
    pub component_ref: String,
    /// List of components this depends on
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<Vec<String>>,
}

/// Algorithm metadata for mapping common algorithms
#[derive(Debug, Clone)]
struct AlgorithmMetadata {
    primitive: String,
    oid: Option<String>,
    crypto_functions: Vec<String>,
}

/// CBOM Generator implementation
pub struct CbomGenerator;

impl CbomGenerator {
    /// Generate CBOM from CryptoScanner findings
    pub fn generate_cbom(
        findings: &[Finding],
        _target_component: Option<String>,
    ) -> Result<CbomDocument, Box<dyn std::error::Error>> {
        let timestamp = Utc::now();
        let serial_number = format!("urn:uuid:{}", Uuid::new_v4());

        // Create tool metadata
        let tools = ToolsMetadata {
            components: Some(vec![]),
            services: Some(vec![ToolService {
                provider: Some(Provider {
                    name: "Link2Trust".to_string(),
                }),
                name: "CryptoScanner".to_string(),
                version: Some("0.1.0".to_string()),
            }]),
        };

        let metadata = CbomMetadata { timestamp, tools };

        // Generate components from findings
        let components = Self::generate_components(findings)?;

        // Generate dependencies (if any)
        let dependencies = Self::generate_dependencies(&components);

        Ok(CbomDocument {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.7".to_string(),
            serial_number,
            version: 1,
            metadata,
            components: if components.is_empty() {
                None
            } else {
                Some(components)
            },
            dependencies: if dependencies.is_empty() {
                None
            } else {
                Some(dependencies)
            },
        })
    }

    /// Generate CBOM components from scan findings
    fn generate_components(
        findings: &[Finding],
    ) -> Result<Vec<CbomComponent>, Box<dyn std::error::Error>> {
        let mut components = Vec::new();
        let mut seen_algorithms: HashMap<String, Vec<&Finding>> = HashMap::new();

        // Group findings by algorithm/library name
        for finding in findings {
            if finding.category == "library" || finding.category == "secret" {
                let key = finding.keyword.clone();
                seen_algorithms.entry(key).or_default().push(finding);
            }
        }

        // Generate components for each unique algorithm
        for (algorithm_name, occurrences) in seen_algorithms {
            let bom_ref = Uuid::new_v4().to_string();
            let metadata = Self::get_algorithm_metadata(&algorithm_name);

            // Collect occurrences
            let evidence_occurrences: Vec<Occurrence> = occurrences
                .iter()
                .map(|f| Occurrence {
                    location: f.file.clone(),
                    line: Some(f.line_number),
                    offset: None,
                    additional_context: Some(f.line_content.clone()),
                })
                .collect();

            let component = CbomComponent {
                component_type: "cryptographic-asset".to_string(),
                bom_ref,
                name: algorithm_name.clone(),
                evidence: Some(Evidence {
                    occurrences: Some(evidence_occurrences),
                }),
                crypto_properties: Some(CryptoProperties {
                    asset_type: "algorithm".to_string(),
                    algorithm_properties: Some(AlgorithmProperties {
                        primitive: metadata.primitive,
                        parameter_set_identifier: Self::infer_parameter_set(&algorithm_name),
                        crypto_functions: Some(metadata.crypto_functions),
                    }),
                    oid: metadata.oid,
                }),
            };

            components.push(component);
        }

        Ok(components)
    }

    /// Get algorithm metadata based on algorithm name
    fn get_algorithm_metadata(algorithm_name: &str) -> AlgorithmMetadata {
        let name_lower = algorithm_name.to_lowercase();

        // SHA algorithms
        if name_lower.contains("sha256") || name_lower == "sha-256" {
            return AlgorithmMetadata {
                primitive: "hash".to_string(),
                oid: Some("2.16.840.1.101.3.4.2.1".to_string()),
                crypto_functions: vec!["digest".to_string()],
            };
        }
        if name_lower.contains("sha384") || name_lower == "sha-384" {
            return AlgorithmMetadata {
                primitive: "hash".to_string(),
                oid: Some("2.16.840.1.101.3.4.2.2".to_string()),
                crypto_functions: vec!["digest".to_string()],
            };
        }
        if name_lower.contains("sha512") || name_lower == "sha-512" {
            return AlgorithmMetadata {
                primitive: "hash".to_string(),
                oid: Some("2.16.840.1.101.3.4.2.3".to_string()),
                crypto_functions: vec!["digest".to_string()],
            };
        }
        if name_lower.contains("sha1") || name_lower == "sha-1" {
            return AlgorithmMetadata {
                primitive: "hash".to_string(),
                oid: Some("1.3.14.3.2.26".to_string()),
                crypto_functions: vec!["digest".to_string()],
            };
        }

        // RSA signature algorithms
        if name_lower.contains("sha256withrsa") {
            return AlgorithmMetadata {
                primitive: "signature".to_string(),
                oid: Some("1.2.840.113549.1.1.11".to_string()),
                crypto_functions: vec!["sign".to_string(), "verify".to_string()],
            };
        }
        if name_lower.contains("sha384withrsa") {
            return AlgorithmMetadata {
                primitive: "signature".to_string(),
                oid: Some("1.2.840.113549.1.1.12".to_string()),
                crypto_functions: vec!["sign".to_string(), "verify".to_string()],
            };
        }
        if name_lower.contains("sha512withrsa") {
            return AlgorithmMetadata {
                primitive: "signature".to_string(),
                oid: Some("1.2.840.113549.1.1.13".to_string()),
                crypto_functions: vec!["sign".to_string(), "verify".to_string()],
            };
        }

        // RSA encryption
        if name_lower.contains("rsa") && !name_lower.contains("with") {
            return AlgorithmMetadata {
                primitive: "asymmetric".to_string(),
                oid: Some("1.2.840.113549.1.1.1".to_string()),
                crypto_functions: vec!["encrypt".to_string(), "decrypt".to_string()],
            };
        }

        // AES
        if name_lower.contains("aes") {
            return AlgorithmMetadata {
                primitive: "block-cipher".to_string(),
                oid: None, // AES has multiple OIDs based on key size
                crypto_functions: vec!["encrypt".to_string(), "decrypt".to_string()],
            };
        }

        // ECDSA
        if name_lower.contains("ecdsa") || name_lower.contains("ec-dsa") {
            return AlgorithmMetadata {
                primitive: "signature".to_string(),
                oid: Some("1.2.840.10045.4.3".to_string()),
                crypto_functions: vec!["sign".to_string(), "verify".to_string()],
            };
        }

        // HMAC
        if name_lower.contains("hmac") {
            return AlgorithmMetadata {
                primitive: "mac".to_string(),
                oid: None,
                crypto_functions: vec!["tag".to_string()],
            };
        }

        // Default/unknown
        AlgorithmMetadata {
            primitive: "unknown".to_string(),
            oid: None,
            crypto_functions: vec![],
        }
    }

    /// Infer parameter set identifier from algorithm name
    fn infer_parameter_set(algorithm_name: &str) -> Option<String> {
        let name_lower = algorithm_name.to_lowercase();

        // Extract key sizes
        if name_lower.contains("256") {
            return Some("256".to_string());
        }
        if name_lower.contains("384") {
            return Some("384".to_string());
        }
        if name_lower.contains("512") {
            return Some("512".to_string());
        }
        if name_lower.contains("2048") {
            return Some("2048".to_string());
        }
        if name_lower.contains("3072") {
            return Some("3072".to_string());
        }
        if name_lower.contains("4096") {
            return Some("4096".to_string());
        }

        None
    }

    /// Generate dependencies between components
    fn generate_dependencies(components: &[CbomComponent]) -> Vec<Dependency> {
        let mut dependencies = Vec::new();

        // Example: If SHA256withRSA is present, it depends on SHA256
        let component_names: HashMap<String, String> = components
            .iter()
            .map(|c| (c.name.clone(), c.bom_ref.clone()))
            .collect();

        for component in components {
            let name_lower = component.name.to_lowercase();

            // Check if this is a composite algorithm
            let mut depends_on = Vec::new();

            if name_lower.contains("withrsa") || name_lower.contains("with-rsa") {
                // Find SHA component
                if name_lower.contains("sha256") {
                    if let Some(sha_ref) = component_names.get("SHA256") {
                        depends_on.push(sha_ref.clone());
                    }
                }
                if name_lower.contains("sha384") {
                    if let Some(sha_ref) = component_names.get("SHA384") {
                        depends_on.push(sha_ref.clone());
                    }
                }
                if name_lower.contains("sha512") {
                    if let Some(sha_ref) = component_names.get("SHA512") {
                        depends_on.push(sha_ref.clone());
                    }
                }
            }

            if !depends_on.is_empty() {
                dependencies.push(Dependency {
                    component_ref: component.bom_ref.clone(),
                    depends_on: Some(depends_on),
                });
            }
        }

        dependencies
    }

    /// Export CBOM to JSON format
    pub fn export_json(cbom: &CbomDocument) -> Result<String, Box<dyn std::error::Error>> {
        Ok(serde_json::to_string_pretty(cbom)?)
    }

    /// Export CBOM to XML format (basic implementation)
    pub fn export_xml(_cbom: &CbomDocument) -> Result<String, Box<dyn std::error::Error>> {
        // XML export would require additional dependencies like quick-xml
        // For now, return a placeholder
        Err("XML export not yet implemented for CycloneDX 1.7 format".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbom_generation() {
        let findings = vec![
            Finding {
                file: "/test/crypto.java".to_string(),
                line_number: 187,
                line_content: "Signature.getInstance(\"SHA256withRSA\")".to_string(),
                match_type: "algorithm".to_string(),
                keyword: "SHA256withRSA".to_string(),
                context: "signature".to_string(),
                version: None,
                language: "Java".to_string(),
                source: "code".to_string(),
                category: "library".to_string(),
            },
            Finding {
                file: "/test/crypto.java".to_string(),
                line_number: 190,
                line_content: "MessageDigest.getInstance(\"SHA256\")".to_string(),
                match_type: "algorithm".to_string(),
                keyword: "SHA256".to_string(),
                context: "hash".to_string(),
                version: None,
                language: "Java".to_string(),
                source: "code".to_string(),
                category: "library".to_string(),
            },
        ];

        let cbom = CbomGenerator::generate_cbom(&findings, Some("test-app".to_string())).unwrap();

        assert_eq!(cbom.spec_version, "1.7");
        assert_eq!(cbom.version, 1);
        assert_eq!(cbom.bom_format, "CycloneDX");
        assert!(cbom.serial_number.starts_with("urn:uuid:"));
        assert!(cbom.components.is_some());

        let components = cbom.components.unwrap();
        assert!(!components.is_empty());

        // Verify component structure
        for component in &components {
            assert_eq!(component.component_type, "cryptographic-asset");
            assert!(component.crypto_properties.is_some());
            assert!(component.evidence.is_some());
        }
    }

    #[test]
    fn test_json_export() {
        let findings = vec![];
        let cbom = CbomGenerator::generate_cbom(&findings, None).unwrap();
        let json = CbomGenerator::export_json(&cbom).unwrap();

        assert!(json.contains("specVersion"));
        assert!(json.contains("1.7"));
        assert!(json.contains("CycloneDX"));
    }

    #[test]
    fn test_algorithm_metadata() {
        let sha256_meta = CbomGenerator::get_algorithm_metadata("SHA256");
        assert_eq!(sha256_meta.primitive, "hash");
        assert_eq!(
            sha256_meta.oid,
            Some("2.16.840.1.101.3.4.2.1".to_string())
        );
        assert!(sha256_meta.crypto_functions.contains(&"digest".to_string()));

        let rsa_sig_meta = CbomGenerator::get_algorithm_metadata("SHA256withRSA");
        assert_eq!(rsa_sig_meta.primitive, "signature");
        assert!(rsa_sig_meta.crypto_functions.contains(&"verify".to_string()));
    }
}
