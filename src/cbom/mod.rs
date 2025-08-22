use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::utils::report::Finding;

/// CycloneDX CBOM (Cryptography Bill of Materials) generator
/// Implements CycloneDX 1.6 specification for cryptographic asset inventory

/// Main CBOM document structure
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CbomDocument {
    /// BOM format identifier (must be "CycloneDX")
    pub bom_format: String,
    /// CycloneDX specification version
    pub spec_version: String,
    /// CBOM document version
    pub version: u32,
    /// Document serial number (RFC 4122 URN format)
    pub serial_number: String,
    /// Document metadata
    pub metadata: CbomMetadata,
    /// List of cryptographic components
    pub components: Vec<CbomComponent>,
    /// Cryptographic declarations
    pub declarations: Option<CbomDeclarations>,
}

/// CBOM metadata
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CbomMetadata {
    /// Timestamp when CBOM was generated
    pub timestamp: DateTime<Utc>,
    /// Tools used to generate CBOM
    pub tools: Vec<CbomTool>,
    /// Component being described
    pub component: CbomComponent,
}

/// Tool information
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CbomTool {
    /// Tool vendor
    pub vendor: String,
    /// Tool name
    pub name: String,
    /// Tool version
    pub version: String,
    /// Tool description
    pub description: Option<String>,
}

/// CBOM component representing cryptographic assets
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CbomComponent {
    /// Component type (library, application, etc.)
    #[serde(rename = "type")]
    pub component_type: String,
    /// Unique identifier
    pub bom_ref: String,
    /// Component name
    pub name: String,
    /// Component version
    pub version: Option<String>,
    /// Component description
    pub description: Option<String>,
    /// Cryptographic properties
    pub crypto_properties: Option<CryptoProperties>,
}

/// Cryptographic properties of a component
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CryptoProperties {
    /// Type of cryptographic asset
    pub asset_type: CryptoAssetType,
    /// Supported algorithms
    pub algorithm_properties: Option<Vec<AlgorithmProperties>>,
    /// Certificate properties (if applicable)
    pub certificate_properties: Option<CertificateProperties>,
    /// Related cryptographic material
    pub related_crypto_material_properties: Option<Vec<RelatedCryptoMaterial>>,
    /// Compliance and certification info
    pub protocol_properties: Option<ProtocolProperties>,
}

/// Types of cryptographic assets
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoAssetType {
    Algorithm,
    Certificate,
    Protocol,
    RelatedCryptoMaterial,
    Key,
    Token,
}

/// Algorithm properties
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmProperties {
    /// Primitive type (e.g., "symmetric-encryption", "hash", "digital-signature")
    pub primitive: String,
    /// Algorithm family (e.g., "aes", "rsa", "ecdsa")
    pub algorithm_name: String,
    /// Key length in bits
    pub key_length: Option<u32>,
    /// Cryptographic strength
    pub cryptographic_strength: Option<u32>,
    /// Whether algorithm is quantum-safe
    pub quantum_safe: Option<bool>,
    /// Classical security level
    pub classical_security_level: Option<u32>,
    /// NIST security level
    pub nist_security_level: Option<u32>,
    /// Additional parameters
    pub parameter_set_identifier: Option<String>,
}

/// Certificate properties
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CertificateProperties {
    /// Certificate subject name
    pub subject_name: Option<String>,
    /// Certificate issuer name
    pub issuer_name: Option<String>,
    /// Certificate not valid before
    pub not_valid_before: Option<DateTime<Utc>>,
    /// Certificate not valid after  
    pub not_valid_after: Option<DateTime<Utc>>,
    /// Certificate signature algorithm
    pub signature_algorithm_ref: Option<String>,
    /// Subject public key algorithm
    pub subject_public_key_algorithm_ref: Option<String>,
    /// Certificate format (e.g., "X.509")
    pub certificate_format: Option<String>,
    /// Certificate extension properties
    pub certificate_extension: Option<Vec<String>>,
}

/// Related cryptographic material
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RelatedCryptoMaterial {
    /// Type of related material
    #[serde(rename = "type")]
    pub material_type: String,
    /// Reference ID
    pub id: String,
    /// State of the material
    pub state: Option<String>,
    /// Algorithm reference
    pub algorithm_ref: Option<String>,
    /// Creation time
    pub creation_time: Option<DateTime<Utc>>,
    /// Activation time
    pub activation_time: Option<DateTime<Utc>>,
    /// Update time
    pub update_time: Option<DateTime<Utc>>,
    /// Expiration time
    pub expiration_time: Option<DateTime<Utc>>,
}

/// Protocol properties
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolProperties {
    /// Protocol type (e.g., "tls", "ipsec")
    #[serde(rename = "type")]
    pub protocol_type: String,
    /// Protocol version
    pub version: Option<String>,
    /// Cipher suites
    pub cipher_suites: Option<Vec<CipherSuite>>,
    /// Supported ikev2 transform types
    pub ikev2_transform_types: Option<Vec<String>>,
    /// Supported cryptographic functions
    pub cryptographic_functions: Option<Vec<String>>,
}

/// Cipher suite definition
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CipherSuite {
    /// Cipher suite name
    pub name: String,
    /// Cipher suite algorithms
    pub algorithms: Vec<String>,
    /// Identifiers (e.g., RFC, IANA)
    pub identifiers: Option<Vec<String>>,
}

/// Cryptographic declarations
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CbomDeclarations {
    /// Assessor information
    pub assessor: Option<String>,
    /// Assessment date
    pub assessment_date: Option<DateTime<Utc>>,
    /// Compliance claims
    pub compliance: Option<Vec<ComplianceClaim>>,
    /// Risk assessments
    pub risk_assessments: Option<Vec<RiskAssessment>>,
}

/// Compliance claim
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceClaim {
    /// Standard name (e.g., "FIPS-140-2", "Common Criteria")
    pub standard: String,
    /// Compliance level
    pub level: Option<String>,
    /// Certification status
    pub status: String,
    /// Certification date
    pub date: Option<DateTime<Utc>>,
    /// Certificate number
    pub certificate_number: Option<String>,
}

/// Risk assessment
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RiskAssessment {
    /// Risk category
    pub category: String,
    /// Risk level (low, medium, high, critical)
    pub level: String,
    /// Risk description
    pub description: String,
    /// Mitigation recommendations
    pub mitigation: Option<String>,
}

/// CBOM Generator implementation
pub struct CbomGenerator;

impl CbomGenerator {
    /// Generate CBOM from CryptoScanner findings
    pub fn generate_cbom(findings: &[Finding], target_component: Option<String>) -> Result<CbomDocument, Box<dyn std::error::Error>> {
        let timestamp = Utc::now();
        // Format serial number per RFC 4122 URN format as required by CycloneDX 1.6
        let serial_number = format!("urn:uuid:{}", Uuid::new_v4().to_string());
        
        // Create tool metadata
        let tool = CbomTool {
            vendor: "Link2Trust".to_string(),
            name: "CryptoScanner".to_string(),
            version: "0.1.0".to_string(),
            description: Some("Cryptographic security analysis tool".to_string()),
        };

        // Create target component
        let target = CbomComponent {
            component_type: "application".to_string(),
            bom_ref: "target-component".to_string(),
            name: target_component.unwrap_or_else(|| "scanned-application".to_string()),
            version: Some("unknown".to_string()),
            description: Some("Application analyzed by CryptoScanner".to_string()),
            crypto_properties: None,
        };

        let metadata = CbomMetadata {
            timestamp,
            tools: vec![tool],
            component: target.clone(),
        };

        // Generate components from findings
        let components = Self::generate_components(findings)?;
        
        // Generate declarations
        let declarations = Self::generate_declarations(findings)?;

        Ok(CbomDocument {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.6".to_string(),
            version: 1,
            serial_number,
            metadata,
            components,
            declarations: Some(declarations),
        })
    }

    /// Generate CBOM components from scan findings
    fn generate_components(findings: &[Finding]) -> Result<Vec<CbomComponent>, Box<dyn std::error::Error>> {
        let mut components = Vec::new();
        let mut processed_libraries: HashSet<String> = HashSet::new();

        // Group findings by library/component
        let mut library_findings: HashMap<String, Vec<&Finding>> = HashMap::new();
        
        for finding in findings {
            if finding.category == "library" {
                let key = format!("{}_{}", finding.keyword, finding.version.as_deref().unwrap_or("unknown"));
                library_findings.entry(key).or_default().push(finding);
            }
        }

        // Generate components for each library
        for (library_key, lib_findings) in library_findings {
            if let Some(first_finding) = lib_findings.first() {
                let component_id = format!("crypto-lib-{}", Uuid::new_v4().to_string()[..8].to_lowercase());
                
                let algorithm_props = Self::infer_algorithm_properties(&first_finding.keyword);
                
                let crypto_properties = CryptoProperties {
                    asset_type: CryptoAssetType::Algorithm,
                    algorithm_properties: Some(algorithm_props),
                    certificate_properties: None,
                    related_crypto_material_properties: None,
                    protocol_properties: None,
                };

                let component = CbomComponent {
                    component_type: "library".to_string(),
                    bom_ref: component_id,
                    name: first_finding.keyword.clone(),
                    version: first_finding.version.clone(),
                    description: Some(format!("Cryptographic library detected in {}", first_finding.file)),
                    crypto_properties: Some(crypto_properties),
                };

                components.push(component);
            }
        }

        // Generate components for keystore files
        for finding in findings {
            if finding.category == "keystore" {
                let component_id = format!("keystore-{}", Uuid::new_v4().to_string()[..8].to_lowercase());
                
                let crypto_properties = match finding.file.split('.').last() {
                    Some("pem") | Some("crt") | Some("cer") => {
                        Some(CryptoProperties {
                            asset_type: CryptoAssetType::Certificate,
                            algorithm_properties: None,
                            certificate_properties: Some(CertificateProperties {
                                subject_name: None,
                                issuer_name: None,
                                not_valid_before: None,
                                not_valid_after: None,
                                signature_algorithm_ref: None,
                                subject_public_key_algorithm_ref: None,
                                certificate_format: Some("X.509".to_string()),
                                certificate_extension: None,
                            }),
                            related_crypto_material_properties: None,
                            protocol_properties: None,
                        })
                    },
                    Some("key") | Some("p12") | Some("jks") | Some("pfx") => {
                        Some(CryptoProperties {
                            asset_type: CryptoAssetType::Key,
                            algorithm_properties: None,
                            certificate_properties: None,
                            related_crypto_material_properties: Some(vec![RelatedCryptoMaterial {
                                material_type: "private-key".to_string(),
                                id: component_id.clone(),
                                state: Some("unknown".to_string()),
                                algorithm_ref: None,
                                creation_time: None,
                                activation_time: None,
                                update_time: None,
                                expiration_time: None,
                            }]),
                            protocol_properties: None,
                        })
                    },
                    _ => None,
                };

                let component = CbomComponent {
                    component_type: "file".to_string(),
                    bom_ref: component_id,
                    name: finding.file.split('/').last().unwrap_or(&finding.file).to_string(),
                    version: None,
                    description: Some(format!("Cryptographic keystore file: {}", finding.file)),
                    crypto_properties,
                };

                components.push(component);
            }
        }

        Ok(components)
    }

    /// Generate cryptographic declarations
    fn generate_declarations(findings: &[Finding]) -> Result<CbomDeclarations, Box<dyn std::error::Error>> {
        let mut risk_assessments = Vec::new();
        
        // Assess hardcoded secrets risk
        let secret_count = findings.iter().filter(|f| f.category == "secret").count();
        if secret_count > 0 {
            let risk_level = match secret_count {
                1..=2 => "medium",
                3..=5 => "high", 
                _ => "critical",
            };
            
            risk_assessments.push(RiskAssessment {
                category: "hardcoded-secrets".to_string(),
                level: risk_level.to_string(),
                description: format!("Found {} hardcoded secrets in codebase", secret_count),
                mitigation: Some("Rotate exposed secrets and implement secure secret management".to_string()),
            });
        }

        // Assess cryptographic library diversity
        let unique_libraries = findings.iter()
            .filter(|f| f.category == "library")
            .map(|f| &f.keyword)
            .collect::<HashSet<_>>()
            .len();
            
        if unique_libraries > 5 {
            risk_assessments.push(RiskAssessment {
                category: "library-complexity".to_string(),
                level: "medium".to_string(),
                description: format!("High cryptographic library diversity ({} unique libraries)", unique_libraries),
                mitigation: Some("Consider consolidating cryptographic implementations".to_string()),
            });
        }

        Ok(CbomDeclarations {
            assessor: Some("CryptoScanner v0.1.0".to_string()),
            assessment_date: Some(Utc::now()),
            compliance: None,
            risk_assessments: if risk_assessments.is_empty() { None } else { Some(risk_assessments) },
        })
    }

    /// Infer algorithm properties from library name
    fn infer_algorithm_properties(library_name: &str) -> Vec<AlgorithmProperties> {
        let library_lower = library_name.to_lowercase();
        let mut algorithms = Vec::new();

        // Common cryptographic libraries and their algorithms
        match library_lower.as_str() {
            name if name.contains("openssl") => {
                algorithms.push(AlgorithmProperties {
                    primitive: "symmetric-encryption".to_string(),
                    algorithm_name: "AES".to_string(),
                    key_length: Some(256),
                    cryptographic_strength: Some(256),
                    quantum_safe: Some(false),
                    classical_security_level: Some(256),
                    nist_security_level: Some(5),
                    parameter_set_identifier: None,
                });
                algorithms.push(AlgorithmProperties {
                    primitive: "digital-signature".to_string(),
                    algorithm_name: "RSA".to_string(),
                    key_length: Some(2048),
                    cryptographic_strength: Some(112),
                    quantum_safe: Some(false),
                    classical_security_level: Some(112),
                    nist_security_level: Some(3),
                    parameter_set_identifier: None,
                });
            },
            name if name.contains("bouncycastle") => {
                algorithms.push(AlgorithmProperties {
                    primitive: "symmetric-encryption".to_string(),
                    algorithm_name: "AES".to_string(),
                    key_length: Some(256),
                    cryptographic_strength: Some(256),
                    quantum_safe: Some(false),
                    classical_security_level: Some(256),
                    nist_security_level: Some(5),
                    parameter_set_identifier: None,
                });
            },
            name if name.contains("crypto") => {
                algorithms.push(AlgorithmProperties {
                    primitive: "hash".to_string(),
                    algorithm_name: "SHA-256".to_string(),
                    key_length: None,
                    cryptographic_strength: Some(256),
                    quantum_safe: Some(false),
                    classical_security_level: Some(256),
                    nist_security_level: Some(5),
                    parameter_set_identifier: None,
                });
            },
            _ => {
                // Generic fallback
                algorithms.push(AlgorithmProperties {
                    primitive: "unknown".to_string(),
                    algorithm_name: library_name.to_string(),
                    key_length: None,
                    cryptographic_strength: None,
                    quantum_safe: Some(false),
                    classical_security_level: None,
                    nist_security_level: None,
                    parameter_set_identifier: None,
                });
            }
        }

        algorithms
    }

    /// Export CBOM to JSON format
    pub fn export_json(cbom: &CbomDocument) -> Result<String, Box<dyn std::error::Error>> {
        Ok(serde_json::to_string_pretty(cbom)?)
    }

    /// Export CBOM to XML format (basic implementation)
    pub fn export_xml(cbom: &CbomDocument) -> Result<String, Box<dyn std::error::Error>> {
        // Basic XML serialization - in production you'd use a proper XML library
        let json = Self::export_json(cbom)?;
        Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<cbom>\n<!-- JSON representation: -->\n<!-- {} -->\n</cbom>", json))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::report::Finding;

    #[test]
    fn test_cbom_generation() {
        let findings = vec![
            Finding {
                file: "/test/crypto.rs".to_string(),
                line_number: 1,
                line_content: "use openssl::crypto;".to_string(),
                match_type: "import".to_string(),
                keyword: "openssl".to_string(),
                context: "import".to_string(),
                version: Some("1.0.0".to_string()),
                language: "Rust".to_string(),
                source: "import".to_string(),
                category: "library".to_string(),
            },
            Finding {
                file: "/test/cert.pem".to_string(),
                line_number: 1,
                line_content: "-----BEGIN CERTIFICATE-----".to_string(),
                match_type: "file".to_string(),
                keyword: "certificate".to_string(),
                context: "file".to_string(),
                version: None,
                language: "PEM".to_string(),
                source: "file".to_string(),
                category: "keystore".to_string(),
            },
        ];

        let cbom = CbomGenerator::generate_cbom(&findings, Some("test-app".to_string())).unwrap();
        
        assert_eq!(cbom.spec_version, "1.6");
        assert_eq!(cbom.version, 1);
        assert_eq!(cbom.metadata.component.name, "test-app");
        assert!(cbom.components.len() >= 2);
        assert!(cbom.declarations.is_some());
    }

    #[test]
    fn test_json_export() {
        let findings = vec![];
        let cbom = CbomGenerator::generate_cbom(&findings, None).unwrap();
        let json = CbomGenerator::export_json(&cbom).unwrap();
        
        assert!(json.contains("specVersion"));
        assert!(json.contains("1.6"));
    }
}
