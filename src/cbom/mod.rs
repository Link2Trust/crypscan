use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::utils::report::Finding;

/// CycloneDX CBOM (Cryptography Bill of Materials) generator
/// Implements CycloneDX 1.6 specification for cryptographic asset inventory
/// Compatible with IBM CBOMKit (CBOMkit-coeus viewer)

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
    /// The component that the BOM represents
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<MetadataComponent>,
}

/// Metadata component (the application being analyzed)
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MetadataComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Tools metadata structure
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ToolsMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<Vec<ToolService>>,
}

/// Tool service information
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ToolService {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<Provider>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Provider information
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Provider {
    pub name: String,
}

/// CBOM component representing cryptographic assets
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CbomComponent {
    /// Component type (must be "cryptographic-asset")
    #[serde(rename = "type")]
    pub component_type: String,
    /// Unique identifier
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    /// Component name (algorithm name, cert name, etc.)
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occurrences: Option<Vec<Occurrence>>,
}

/// Occurrence of a cryptographic component
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Occurrence {
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

/// Cryptographic properties of a component (CycloneDX 1.6)
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CryptoProperties {
    /// Type of cryptographic asset: algorithm, certificate, protocol, related-crypto-material
    pub asset_type: String,
    /// Algorithm properties (when assetType is "algorithm")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm_properties: Option<AlgorithmProperties>,
    /// Certificate properties (when assetType is "certificate")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_properties: Option<CertificateProperties>,
    /// Related crypto material properties (when assetType is "related-crypto-material")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_crypto_material_properties: Option<RelatedCryptoMaterialProperties>,
    /// OID (Object Identifier)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
}

/// Algorithm properties (CycloneDX 1.6 enum values)
/// primitive: drbg, mac, block-cipher, stream-cipher, signature, hash, pke, xof, kdf, key-agree, kem, ae, other, unknown
/// cryptoFunctions: generate, keygen, encrypt, decrypt, digest, tag, keyderive, sign, verify, encapsulate, decapsulate, other
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmProperties {
    /// Primitive type
    pub primitive: String,
    /// Parameter set identifier (e.g., key size)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter_set_identifier: Option<String>,
    /// Mode of operation (e.g., "gcm", "cbc")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Cryptographic functions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_functions: Option<Vec<String>>,
}

/// Certificate properties (CycloneDX 1.6)
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CertificateProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_extension: Option<String>,
}

/// Related crypto material properties (CycloneDX 1.6)
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RelatedCryptoMaterialProperties {
    /// Type of crypto material
    #[serde(rename = "type")]
    pub material_type: String,
    /// Format of the material
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// Dependency relationship
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    #[serde(rename = "ref")]
    pub component_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Internal types for algorithm extraction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ExtractedAsset {
    name: String,
    asset_type: AssetKind,
    primitive: Option<String>,
    oid: Option<String>,
    functions: Vec<String>,
    param_set: Option<String>,
    mode: Option<String>,
    cert_format: Option<String>,
    cert_extension: Option<String>,
    material_type: Option<String>,
    material_format: Option<String>,
    file: String,
    line: usize,
    context: String,
}

#[derive(Debug, Clone, PartialEq)]
enum AssetKind {
    Algorithm,
    Certificate,
    RelatedCryptoMaterial,
}

impl AssetKind {
    fn as_str(&self) -> &str {
        match self {
            AssetKind::Algorithm => "algorithm",
            AssetKind::Certificate => "certificate",
            AssetKind::RelatedCryptoMaterial => "related-crypto-material",
        }
    }
}

#[derive(Debug, Clone)]
struct AlgorithmMeta {
    primitive: String,
    oid: Option<String>,
    functions: Vec<String>,
    mode: Option<String>,
}

// ---------------------------------------------------------------------------
// CBOM Generator
// ---------------------------------------------------------------------------

pub struct CbomGenerator;

impl CbomGenerator {
    /// Generate CBOM from CryptoScanner findings
    pub fn generate_cbom(
        findings: &[Finding],
        target_component: Option<String>,
    ) -> Result<CbomDocument, Box<dyn std::error::Error>> {
        let timestamp = Utc::now();
        let serial_number = format!("urn:uuid:{}", Uuid::new_v4());

        let tools = ToolsMetadata {
            components: Some(vec![]),
            services: Some(vec![ToolService {
                provider: Some(Provider {
                    name: "Link2Trust".to_string(),
                }),
                name: "CryptoScanner".to_string(),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }]),
        };

        let metadata_component = target_component.map(|name| MetadataComponent {
            component_type: "application".to_string(),
            name,
            version: None,
        });

        let metadata = CbomMetadata {
            timestamp,
            tools,
            component: metadata_component,
        };

        let components = Self::generate_components(findings)?;
        let dependencies = Self::generate_dependencies(&components);

        Ok(CbomDocument {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.6".to_string(),
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

    // -----------------------------------------------------------------------
    // Component generation
    // -----------------------------------------------------------------------

    fn generate_components(
        findings: &[Finding],
    ) -> Result<Vec<CbomComponent>, Box<dyn std::error::Error>> {
        let mut assets: Vec<ExtractedAsset> = Vec::new();

        for finding in findings {
            if Self::is_false_positive(finding) {
                continue;
            }

            match finding.category.as_str() {
                "keystore" => {
                    if let Some(asset) = Self::extract_keystore_asset(finding) {
                        assets.push(asset);
                    }
                }
                "library" => {
                    assets.extend(Self::extract_library_assets(finding));
                }
                "secret" => {
                    if let Some(asset) = Self::extract_secret_asset(finding) {
                        assets.push(asset);
                    }
                }
                _ => {}
            }
        }

        Self::build_components(assets)
    }

    /// Build CBOM components from extracted assets, grouping by name+asset_type
    fn build_components(
        assets: Vec<ExtractedAsset>,
    ) -> Result<Vec<CbomComponent>, Box<dyn std::error::Error>> {
        let mut groups: HashMap<String, Vec<ExtractedAsset>> = HashMap::new();
        for asset in assets {
            let key = format!("{}::{}", asset.asset_type.as_str(), asset.name);
            groups.entry(key).or_default().push(asset);
        }

        let mut components = Vec::new();
        for (_key, group) in groups {
            let first = &group[0];
            let bom_ref = Uuid::new_v4().to_string();

            let occurrences: Vec<Occurrence> = group
                .iter()
                .map(|a| Occurrence {
                    location: a.file.clone(),
                    line: Some(a.line),
                    offset: None,
                    additional_context: Some(a.context.clone()),
                })
                .collect();

            let crypto_properties = match first.asset_type {
                AssetKind::Algorithm => {
                    let mut all_functions: Vec<String> = group
                        .iter()
                        .flat_map(|a| a.functions.clone())
                        .collect();
                    all_functions.sort();
                    all_functions.dedup();

                    CryptoProperties {
                        asset_type: "algorithm".to_string(),
                        algorithm_properties: Some(AlgorithmProperties {
                            primitive: first.primitive.clone().unwrap_or_else(|| "unknown".to_string()),
                            parameter_set_identifier: first.param_set.clone(),
                            mode: first.mode.clone(),
                            crypto_functions: if all_functions.is_empty() {
                                None
                            } else {
                                Some(all_functions)
                            },
                        }),
                        certificate_properties: None,
                        related_crypto_material_properties: None,
                        oid: first.oid.clone(),
                    }
                }
                AssetKind::Certificate => CryptoProperties {
                    asset_type: "certificate".to_string(),
                    algorithm_properties: None,
                    certificate_properties: Some(CertificateProperties {
                        subject_name: None,
                        issuer_name: None,
                        certificate_format: first.cert_format.clone(),
                        certificate_extension: first.cert_extension.clone(),
                    }),
                    related_crypto_material_properties: None,
                    oid: None,
                },
                AssetKind::RelatedCryptoMaterial => CryptoProperties {
                    asset_type: "related-crypto-material".to_string(),
                    algorithm_properties: None,
                    certificate_properties: None,
                    related_crypto_material_properties: Some(RelatedCryptoMaterialProperties {
                        material_type: first
                            .material_type
                            .clone()
                            .unwrap_or_else(|| "unknown".to_string()),
                        format: first.material_format.clone(),
                    }),
                    oid: None,
                },
            };

            components.push(CbomComponent {
                component_type: "cryptographic-asset".to_string(),
                bom_ref,
                name: first.name.clone(),
                evidence: Some(Evidence {
                    occurrences: Some(occurrences),
                }),
                crypto_properties: Some(crypto_properties),
            });
        }

        Ok(components)
    }

    // -----------------------------------------------------------------------
    // False positive detection
    // -----------------------------------------------------------------------

    fn is_false_positive(finding: &Finding) -> bool {
        let line = &finding.line_content;
        let keyword = &finding.keyword;

        // URL paths containing "crypto" or "ssl" are not actual crypto usage
        if line.contains("http://") || line.contains("https://") {
            if keyword == "crypto" || keyword == "ssl" {
                return true;
            }
        }

        // REST API path matchers are not crypto usage
        if line.contains("requestMatchers") || line.contains("api/v1/crypto") {
            if keyword == "crypto" {
                return true;
            }
        }

        // YAML config keys like "ssl:" are not library imports
        if finding.match_type == "import" && keyword == "ssl" {
            let trimmed = line.trim();
            if trimmed == "ssl:" || trimmed.starts_with("ssl:") {
                return true;
            }
        }

        // curl commands hitting crypto endpoints
        if line.contains("curl") && keyword == "crypto" {
            return true;
        }

        false
    }

    // -----------------------------------------------------------------------
    // Keystore finding extraction
    // -----------------------------------------------------------------------

    fn extract_keystore_asset(finding: &Finding) -> Option<ExtractedAsset> {
        let file_path = &finding.file;
        let file_name = file_path
            .rsplit('/')
            .next()
            .unwrap_or(file_path)
            .to_lowercase();

        let keyword = finding.keyword.as_str();

        match keyword {
            "pem" => {
                if file_name.contains("cert") || (file_name.contains("ca-") && !file_name.contains("key")) {
                    Some(ExtractedAsset {
                        name: file_name.clone(),
                        asset_type: AssetKind::Certificate,
                        primitive: None,
                        oid: None,
                        functions: vec![],
                        param_set: None,
                        mode: None,
                        cert_format: Some("X.509".to_string()),
                        cert_extension: Some("pem".to_string()),
                        material_type: None,
                        material_format: None,
                        file: finding.file.clone(),
                        line: finding.line_number,
                        context: finding.context.clone(),
                    })
                } else if file_name.contains("key") {
                    Some(ExtractedAsset {
                        name: file_name.clone(),
                        asset_type: AssetKind::RelatedCryptoMaterial,
                        primitive: None,
                        oid: None,
                        functions: vec![],
                        param_set: None,
                        mode: None,
                        cert_format: None,
                        cert_extension: None,
                        material_type: Some("private-key".to_string()),
                        material_format: Some("PEM".to_string()),
                        file: finding.file.clone(),
                        line: finding.line_number,
                        context: finding.context.clone(),
                    })
                } else {
                    Some(ExtractedAsset {
                        name: file_name.clone(),
                        asset_type: AssetKind::Certificate,
                        primitive: None,
                        oid: None,
                        functions: vec![],
                        param_set: None,
                        mode: None,
                        cert_format: Some("X.509".to_string()),
                        cert_extension: Some("pem".to_string()),
                        material_type: None,
                        material_format: None,
                        file: finding.file.clone(),
                        line: finding.line_number,
                        context: finding.context.clone(),
                    })
                }
            }
            "p12" | "pfx" => Some(ExtractedAsset {
                name: file_name.clone(),
                asset_type: AssetKind::RelatedCryptoMaterial,
                primitive: None,
                oid: None,
                functions: vec![],
                param_set: None,
                mode: None,
                cert_format: None,
                cert_extension: None,
                material_type: Some("key".to_string()),
                material_format: Some("PKCS12".to_string()),
                file: finding.file.clone(),
                line: finding.line_number,
                context: finding.context.clone(),
            }),
            "jks" => Some(ExtractedAsset {
                name: file_name.clone(),
                asset_type: AssetKind::RelatedCryptoMaterial,
                primitive: None,
                oid: None,
                functions: vec![],
                param_set: None,
                mode: None,
                cert_format: None,
                cert_extension: None,
                material_type: Some("key".to_string()),
                material_format: Some("JKS".to_string()),
                file: finding.file.clone(),
                line: finding.line_number,
                context: finding.context.clone(),
            }),
            _ => None,
        }
    }

    // -----------------------------------------------------------------------
    // Library finding extraction
    // -----------------------------------------------------------------------

    fn extract_library_assets(finding: &Finding) -> Vec<ExtractedAsset> {
        let mut assets = Vec::new();
        let keyword = finding.keyword.as_str();

        match keyword {
            "openssl" => {
                if let Some(asset) = Self::extract_openssl_asset(finding) {
                    assets.push(asset);
                }
            }
            "java.security" | "javax.crypto" => {
                if let Some(asset) = Self::extract_java_crypto_asset(finding) {
                    assets.push(asset);
                }
            }
            "bouncycastle" => {
                if let Some(asset) = Self::extract_bouncycastle_asset(finding) {
                    assets.push(asset);
                }
            }
            _ => {
                let meta = Self::get_algorithm_metadata(keyword);
                if meta.primitive != "unknown" {
                    assets.push(ExtractedAsset {
                        name: keyword.to_string(),
                        asset_type: AssetKind::Algorithm,
                        primitive: Some(meta.primitive),
                        oid: meta.oid,
                        functions: meta.functions,
                        param_set: Self::infer_parameter_set(&finding.line_content),
                        mode: meta.mode,
                        cert_format: None,
                        cert_extension: None,
                        material_type: None,
                        material_format: None,
                        file: finding.file.clone(),
                        line: finding.line_number,
                        context: finding.line_content.clone(),
                    });
                }
            }
        }

        assets
    }

    /// Extract algorithm from openssl CLI commands
    fn extract_openssl_asset(finding: &Finding) -> Option<ExtractedAsset> {
        let line = finding.line_content.to_lowercase();

        if line.contains("genrsa") {
            let key_size = Self::extract_number_from_line(&line);
            return Some(ExtractedAsset {
                name: format!("RSA{}", key_size.as_deref().map(|s| format!("-{}", s)).unwrap_or_default()),
                asset_type: AssetKind::Algorithm,
                primitive: Some("pke".to_string()),
                oid: Some("1.2.840.113549.1.1.1".to_string()),
                functions: vec!["keygen".to_string()],
                param_set: key_size,
                mode: None,
                cert_format: None,
                cert_extension: None,
                material_type: None,
                material_format: None,
                file: finding.file.clone(),
                line: finding.line_number,
                context: finding.line_content.clone(),
            });
        }

        if line.contains("req") && line.contains("x509") {
            return Some(ExtractedAsset {
                name: "X.509-Certificate".to_string(),
                asset_type: AssetKind::Certificate,
                primitive: None,
                oid: None,
                functions: vec![],
                param_set: None,
                mode: None,
                cert_format: Some("X.509".to_string()),
                cert_extension: Some("pem".to_string()),
                material_type: None,
                material_format: None,
                file: finding.file.clone(),
                line: finding.line_number,
                context: finding.line_content.clone(),
            });
        }

        if line.contains("x509") && (line.contains("-req") || line.contains("verify")) {
            return Some(ExtractedAsset {
                name: "X.509-Certificate".to_string(),
                asset_type: AssetKind::Certificate,
                primitive: None,
                oid: None,
                functions: vec![],
                param_set: None,
                mode: None,
                cert_format: Some("X.509".to_string()),
                cert_extension: Some("pem".to_string()),
                material_type: None,
                material_format: None,
                file: finding.file.clone(),
                line: finding.line_number,
                context: finding.line_content.clone(),
            });
        }

        if line.contains("pkcs12") {
            return Some(ExtractedAsset {
                name: "PKCS12-Keystore".to_string(),
                asset_type: AssetKind::RelatedCryptoMaterial,
                primitive: None,
                oid: None,
                functions: vec![],
                param_set: None,
                mode: None,
                cert_format: None,
                cert_extension: None,
                material_type: Some("key".to_string()),
                material_format: Some("PKCS12".to_string()),
                file: finding.file.clone(),
                line: finding.line_number,
                context: finding.line_content.clone(),
            });
        }

        if line.contains("verify") {
            return Some(ExtractedAsset {
                name: "X.509-Certificate".to_string(),
                asset_type: AssetKind::Certificate,
                primitive: None,
                oid: None,
                functions: vec![],
                param_set: None,
                mode: None,
                cert_format: Some("X.509".to_string()),
                cert_extension: Some("pem".to_string()),
                material_type: None,
                material_format: None,
                file: finding.file.clone(),
                line: finding.line_number,
                context: finding.line_content.clone(),
            });
        }

        if line.contains("genpkey") && line.contains("ec") {
            return Some(ExtractedAsset {
                name: "ECDSA".to_string(),
                asset_type: AssetKind::Algorithm,
                primitive: Some("signature".to_string()),
                oid: Some("1.2.840.10045.4.3".to_string()),
                functions: vec!["keygen".to_string()],
                param_set: None,
                mode: None,
                cert_format: None,
                cert_extension: None,
                material_type: None,
                material_format: None,
                file: finding.file.clone(),
                line: finding.line_number,
                context: finding.line_content.clone(),
            });
        }

        None
    }

    /// Extract crypto primitives from Java security imports and inline usage
    fn extract_java_crypto_asset(finding: &Finding) -> Option<ExtractedAsset> {
        let line = &finding.line_content;

        if line.contains("Signature") && !line.contains("ContentSigner") {
            return Some(Self::make_algorithm_asset(
                "Signature",
                "signature",
                None,
                vec!["sign".to_string(), "verify".to_string()],
                finding,
            ));
        }

        if line.contains("SecureRandom") {
            return Some(Self::make_algorithm_asset(
                "SecureRandom",
                "drbg",
                None,
                vec!["generate".to_string()],
                finding,
            ));
        }

        if line.contains("ECGenParameterSpec") {
            return Some(Self::make_algorithm_asset(
                "EC",
                "key-agree",
                Some("1.2.840.10045.2.1"),
                vec!["keygen".to_string()],
                finding,
            ));
        }

        if line.contains("DSAGenParameterSpec") {
            return Some(Self::make_algorithm_asset(
                "DSA",
                "signature",
                Some("1.2.840.10040.4.1"),
                vec!["keygen".to_string(), "sign".to_string(), "verify".to_string()],
                finding,
            ));
        }

        if line.contains("DHParameterSpec") {
            return Some(Self::make_algorithm_asset(
                "DH",
                "key-agree",
                Some("1.2.840.113549.1.3.1"),
                vec!["keygen".to_string()],
                finding,
            ));
        }

        if line.contains("GCMParameterSpec") {
            return Some(ExtractedAsset {
                name: "AES-GCM".to_string(),
                asset_type: AssetKind::Algorithm,
                primitive: Some("ae".to_string()),
                oid: None,
                functions: vec!["encrypt".to_string(), "decrypt".to_string(), "tag".to_string()],
                param_set: None,
                mode: Some("gcm".to_string()),
                cert_format: None,
                cert_extension: None,
                material_type: None,
                material_format: None,
                file: finding.file.clone(),
                line: finding.line_number,
                context: finding.line_content.clone(),
            });
        }

        if line.contains("IvParameterSpec") {
            return Some(ExtractedAsset {
                name: "AES-CBC".to_string(),
                asset_type: AssetKind::Algorithm,
                primitive: Some("block-cipher".to_string()),
                oid: None,
                functions: vec!["encrypt".to_string(), "decrypt".to_string()],
                param_set: None,
                mode: Some("cbc".to_string()),
                cert_format: None,
                cert_extension: None,
                material_type: None,
                material_format: None,
                file: finding.file.clone(),
                line: finding.line_number,
                context: finding.line_content.clone(),
            });
        }

        if line.contains("AEADBadTagException") {
            return Some(ExtractedAsset {
                name: "AES-GCM".to_string(),
                asset_type: AssetKind::Algorithm,
                primitive: Some("ae".to_string()),
                oid: None,
                functions: vec!["encrypt".to_string(), "decrypt".to_string(), "tag".to_string()],
                param_set: None,
                mode: Some("gcm".to_string()),
                cert_format: None,
                cert_extension: None,
                material_type: None,
                material_format: None,
                file: finding.file.clone(),
                line: finding.line_number,
                context: finding.line_content.clone(),
            });
        }

        if line.contains("javax.crypto.Mac") || (line.contains("Mac") && line.contains("getInstance")) {
            return Some(Self::make_algorithm_asset(
                "HMAC",
                "mac",
                None,
                vec!["tag".to_string()],
                finding,
            ));
        }

        if line.contains("Cipher") && !line.contains("CipherSuite") {
            if line.contains("ENCRYPT_MODE") {
                return Some(Self::make_algorithm_asset(
                    "AES",
                    "block-cipher",
                    None,
                    vec!["encrypt".to_string()],
                    finding,
                ));
            }
            if line.contains("DECRYPT_MODE") {
                return Some(Self::make_algorithm_asset(
                    "AES",
                    "block-cipher",
                    None,
                    vec!["decrypt".to_string()],
                    finding,
                ));
            }
            if line.contains("WRAP_MODE") || line.contains("UNWRAP_MODE") {
                return Some(Self::make_algorithm_asset(
                    "AES-KeyWrap",
                    "block-cipher",
                    None,
                    vec!["encrypt".to_string(), "decrypt".to_string()],
                    finding,
                ));
            }
            if line.contains("getInstance") {
                return Some(Self::make_algorithm_asset(
                    "AES",
                    "block-cipher",
                    None,
                    vec!["encrypt".to_string(), "decrypt".to_string()],
                    finding,
                ));
            }
        }

        if line.contains("KeyAgreement") {
            return Some(Self::make_algorithm_asset(
                "KeyAgreement",
                "key-agree",
                None,
                vec!["keyderive".to_string()],
                finding,
            ));
        }

        if line.contains("KeyPairGenerator") || (line.contains("KeyPair") && !line.contains("KeyPairGenerator")) {
            return Some(Self::make_algorithm_asset(
                "KeyPair",
                "pke",
                None,
                vec!["keygen".to_string()],
                finding,
            ));
        }

        if line.contains("KeyGenerator") || line.contains("SecretKey") {
            return Some(Self::make_algorithm_asset(
                "AES",
                "block-cipher",
                None,
                vec!["keygen".to_string()],
                finding,
            ));
        }

        if line.contains("X509Certificate") || line.contains("CertificateExpired") || line.contains("CertificateNotYet") {
            return Some(ExtractedAsset {
                name: "X.509-Certificate".to_string(),
                asset_type: AssetKind::Certificate,
                primitive: None,
                oid: None,
                functions: vec![],
                param_set: None,
                mode: None,
                cert_format: Some("X.509".to_string()),
                cert_extension: None,
                material_type: None,
                material_format: None,
                file: finding.file.clone(),
                line: finding.line_number,
                context: finding.line_content.clone(),
            });
        }

        if line.contains("KeyStore") && !line.contains("KeyStoreException") {
            return Some(ExtractedAsset {
                name: "KeyStore".to_string(),
                asset_type: AssetKind::RelatedCryptoMaterial,
                primitive: None,
                oid: None,
                functions: vec![],
                param_set: None,
                mode: None,
                cert_format: None,
                cert_extension: None,
                material_type: Some("key".to_string()),
                material_format: None,
                file: finding.file.clone(),
                line: finding.line_number,
                context: finding.line_content.clone(),
            });
        }

        if line.contains("KeyFactory") || line.contains("PublicKey") || line.contains("PrivateKey") {
            return Some(Self::make_algorithm_asset(
                "KeyPair",
                "pke",
                None,
                vec!["keygen".to_string()],
                finding,
            ));
        }

        if line.contains("X509EncodedKeySpec") {
            return Some(Self::make_algorithm_asset(
                "KeyPair",
                "pke",
                None,
                vec!["keygen".to_string()],
                finding,
            ));
        }

        None
    }

    /// Extract crypto from Bouncy Castle imports
    fn extract_bouncycastle_asset(finding: &Finding) -> Option<ExtractedAsset> {
        let line = &finding.line_content;

        if line.contains("CertificateBuilder") || line.contains("CertificateConverter") || line.contains("X500Name") {
            return Some(ExtractedAsset {
                name: "X.509-Certificate".to_string(),
                asset_type: AssetKind::Certificate,
                primitive: None,
                oid: None,
                functions: vec![],
                param_set: None,
                mode: None,
                cert_format: Some("X.509".to_string()),
                cert_extension: None,
                material_type: None,
                material_format: None,
                file: finding.file.clone(),
                line: finding.line_number,
                context: finding.line_content.clone(),
            });
        }

        if line.contains("ContentSigner") || line.contains("SignerBuilder") {
            return Some(Self::make_algorithm_asset(
                "Signature",
                "signature",
                None,
                vec!["sign".to_string()],
                finding,
            ));
        }

        None
    }

    // -----------------------------------------------------------------------
    // Secret finding extraction
    // -----------------------------------------------------------------------

    fn extract_secret_asset(finding: &Finding) -> Option<ExtractedAsset> {
        Some(ExtractedAsset {
            name: format!("Hardcoded-{}", finding.keyword),
            asset_type: AssetKind::RelatedCryptoMaterial,
            primitive: None,
            oid: None,
            functions: vec![],
            param_set: None,
            mode: None,
            cert_format: None,
            cert_extension: None,
            material_type: Some("password".to_string()),
            material_format: None,
            file: finding.file.clone(),
            line: finding.line_number,
            context: finding.line_content.clone(),
        })
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_algorithm_asset(
        name: &str,
        primitive: &str,
        oid: Option<&str>,
        functions: Vec<String>,
        finding: &Finding,
    ) -> ExtractedAsset {
        ExtractedAsset {
            name: name.to_string(),
            asset_type: AssetKind::Algorithm,
            primitive: Some(primitive.to_string()),
            oid: oid.map(|s| s.to_string()),
            functions,
            param_set: None,
            mode: None,
            cert_format: None,
            cert_extension: None,
            material_type: None,
            material_format: None,
            file: finding.file.clone(),
            line: finding.line_number,
            context: finding.line_content.clone(),
        }
    }

    /// Extract a number (key size) from a line
    fn extract_number_from_line(line: &str) -> Option<String> {
        for word in line.split_whitespace().rev() {
            if let Ok(n) = word.parse::<u32>() {
                if n >= 128 {
                    return Some(n.to_string());
                }
            }
        }
        None
    }

    /// Get algorithm metadata for well-known algorithm names
    fn get_algorithm_metadata(algorithm_name: &str) -> AlgorithmMeta {
        let name_lower = algorithm_name.to_lowercase();

        // HMAC (check before SHA to avoid false matches on HMAC-SHA256)
        if name_lower.contains("hmac") {
            return AlgorithmMeta {
                primitive: "mac".to_string(),
                oid: None,
                functions: vec!["tag".to_string()],
                mode: None,
            };
        }

        // SHA family
        if name_lower.contains("sha256") || name_lower == "sha-256" {
            return AlgorithmMeta {
                primitive: "hash".to_string(),
                oid: Some("2.16.840.1.101.3.4.2.1".to_string()),
                functions: vec!["digest".to_string()],
                mode: None,
            };
        }
        if name_lower.contains("sha384") || name_lower == "sha-384" {
            return AlgorithmMeta {
                primitive: "hash".to_string(),
                oid: Some("2.16.840.1.101.3.4.2.2".to_string()),
                functions: vec!["digest".to_string()],
                mode: None,
            };
        }
        if name_lower.contains("sha512") || name_lower == "sha-512" {
            return AlgorithmMeta {
                primitive: "hash".to_string(),
                oid: Some("2.16.840.1.101.3.4.2.3".to_string()),
                functions: vec!["digest".to_string()],
                mode: None,
            };
        }
        if name_lower.contains("sha1") || name_lower == "sha-1" {
            return AlgorithmMeta {
                primitive: "hash".to_string(),
                oid: Some("1.3.14.3.2.26".to_string()),
                functions: vec!["digest".to_string()],
                mode: None,
            };
        }

        // RSA signature algorithms
        if name_lower.contains("sha256withrsa") {
            return AlgorithmMeta {
                primitive: "signature".to_string(),
                oid: Some("1.2.840.113549.1.1.11".to_string()),
                functions: vec!["sign".to_string(), "verify".to_string()],
                mode: None,
            };
        }
        if name_lower.contains("sha384withrsa") {
            return AlgorithmMeta {
                primitive: "signature".to_string(),
                oid: Some("1.2.840.113549.1.1.12".to_string()),
                functions: vec!["sign".to_string(), "verify".to_string()],
                mode: None,
            };
        }
        if name_lower.contains("sha512withrsa") {
            return AlgorithmMeta {
                primitive: "signature".to_string(),
                oid: Some("1.2.840.113549.1.1.13".to_string()),
                functions: vec!["sign".to_string(), "verify".to_string()],
                mode: None,
            };
        }

        // RSA encryption (pke = public-key encryption)
        if name_lower.contains("rsa") && !name_lower.contains("with") {
            return AlgorithmMeta {
                primitive: "pke".to_string(),
                oid: Some("1.2.840.113549.1.1.1".to_string()),
                functions: vec!["encrypt".to_string(), "decrypt".to_string()],
                mode: None,
            };
        }

        // AES-GCM (authenticated encryption)
        if name_lower.contains("aes") && name_lower.contains("gcm") {
            return AlgorithmMeta {
                primitive: "ae".to_string(),
                oid: None,
                functions: vec!["encrypt".to_string(), "decrypt".to_string(), "tag".to_string()],
                mode: Some("gcm".to_string()),
            };
        }

        // AES (block cipher)
        if name_lower.contains("aes") {
            return AlgorithmMeta {
                primitive: "block-cipher".to_string(),
                oid: None,
                functions: vec!["encrypt".to_string(), "decrypt".to_string()],
                mode: None,
            };
        }

        // ECDSA
        if name_lower.contains("ecdsa") || name_lower.contains("ec-dsa") {
            return AlgorithmMeta {
                primitive: "signature".to_string(),
                oid: Some("1.2.840.10045.4.3".to_string()),
                functions: vec!["sign".to_string(), "verify".to_string()],
                mode: None,
            };
        }

        // ECDH
        if name_lower.contains("ecdh") {
            return AlgorithmMeta {
                primitive: "key-agree".to_string(),
                oid: Some("1.2.840.10045.2.1".to_string()),
                functions: vec!["keyderive".to_string()],
                mode: None,
            };
        }

        // DH
        if name_lower == "dh" || name_lower == "diffie-hellman" {
            return AlgorithmMeta {
                primitive: "key-agree".to_string(),
                oid: Some("1.2.840.113549.1.3.1".to_string()),
                functions: vec!["keyderive".to_string()],
                mode: None,
            };
        }

        // DSA
        if name_lower == "dsa" {
            return AlgorithmMeta {
                primitive: "signature".to_string(),
                oid: Some("1.2.840.10040.4.1".to_string()),
                functions: vec!["sign".to_string(), "verify".to_string()],
                mode: None,
            };
        }

        AlgorithmMeta {
            primitive: "unknown".to_string(),
            oid: None,
            functions: vec![],
            mode: None,
        }
    }

    /// Infer parameter set identifier from text
    fn infer_parameter_set(text: &str) -> Option<String> {
        let name_lower = text.to_lowercase();

        if name_lower.contains("4096") {
            return Some("4096".to_string());
        }
        if name_lower.contains("3072") {
            return Some("3072".to_string());
        }
        if name_lower.contains("2048") {
            return Some("2048".to_string());
        }
        if name_lower.contains("512") && !name_lower.contains("sha512") {
            return Some("512".to_string());
        }
        if name_lower.contains("384") && !name_lower.contains("sha384") {
            return Some("384".to_string());
        }
        if name_lower.contains("256") && !name_lower.contains("sha256") {
            return Some("256".to_string());
        }
        if name_lower.contains("128") {
            return Some("128".to_string());
        }

        None
    }

    /// Generate dependencies between components
    fn generate_dependencies(components: &[CbomComponent]) -> Vec<Dependency> {
        let mut dependencies = Vec::new();

        let component_names: HashMap<String, String> = components
            .iter()
            .map(|c| (c.name.clone(), c.bom_ref.clone()))
            .collect();

        for component in components {
            let name_lower = component.name.to_lowercase();
            let mut depends_on = Vec::new();

            if name_lower.contains("withrsa") || name_lower.contains("with-rsa") {
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
        Err("XML export not yet implemented for CycloneDX 1.6 format".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cbom_generation_spec_version() {
        let findings = vec![Finding {
            file: "/test/crypto.java".to_string(),
            line_number: 10,
            line_content: "import java.security.Signature;".to_string(),
            match_type: "import".to_string(),
            keyword: "java.security".to_string(),
            context: "import".to_string(),
            version: None,
            language: "Java".to_string(),
            source: "import".to_string(),
            category: "library".to_string(),
        }];

        let cbom = CbomGenerator::generate_cbom(&findings, Some("test-app".to_string())).unwrap();

        assert_eq!(cbom.spec_version, "1.6");
        assert_eq!(cbom.bom_format, "CycloneDX");
        assert_eq!(cbom.version, 1);
        assert!(cbom.serial_number.starts_with("urn:uuid:"));

        let meta_comp = cbom.metadata.component.as_ref().unwrap();
        assert_eq!(meta_comp.name, "test-app");
        assert_eq!(meta_comp.component_type, "application");
    }

    #[test]
    fn test_keystore_findings_included() {
        let findings = vec![
            Finding {
                file: "/certs/ca-cert.pem".to_string(),
                line_number: 0,
                line_content: "".to_string(),
                match_type: "keystore".to_string(),
                keyword: "pem".to_string(),
                context: "PEM file".to_string(),
                version: None,
                language: "Binary/File".to_string(),
                source: "file extension".to_string(),
                category: "keystore".to_string(),
            },
            Finding {
                file: "/certs/server-key.pem".to_string(),
                line_number: 0,
                line_content: "".to_string(),
                match_type: "keystore".to_string(),
                keyword: "pem".to_string(),
                context: "PEM file".to_string(),
                version: None,
                language: "Binary/File".to_string(),
                source: "file extension".to_string(),
                category: "keystore".to_string(),
            },
            Finding {
                file: "/certs/server.p12".to_string(),
                line_number: 0,
                line_content: "".to_string(),
                match_type: "keystore".to_string(),
                keyword: "p12".to_string(),
                context: "PKCS#12 Keystore".to_string(),
                version: None,
                language: "Binary/File".to_string(),
                source: "file extension".to_string(),
                category: "keystore".to_string(),
            },
        ];

        let cbom = CbomGenerator::generate_cbom(&findings, None).unwrap();
        let components = cbom.components.unwrap();
        assert!(!components.is_empty(), "Keystore findings should produce components");

        let asset_types: Vec<String> = components
            .iter()
            .filter_map(|c| c.crypto_properties.as_ref())
            .map(|p| p.asset_type.clone())
            .collect();

        assert!(asset_types.contains(&"certificate".to_string()));
        assert!(asset_types.contains(&"related-crypto-material".to_string()));
    }

    #[test]
    fn test_openssl_algorithm_extraction() {
        let findings = vec![Finding {
            file: "/scripts/gen.sh".to_string(),
            line_number: 10,
            line_content: "openssl genrsa -out key.pem 4096".to_string(),
            match_type: "use".to_string(),
            keyword: "openssl".to_string(),
            context: "use".to_string(),
            version: None,
            language: "Shell".to_string(),
            source: "use".to_string(),
            category: "library".to_string(),
        }];

        let cbom = CbomGenerator::generate_cbom(&findings, None).unwrap();
        let components = cbom.components.unwrap();

        let rsa = components
            .iter()
            .find(|c| c.name.contains("RSA"))
            .expect("Should find RSA component");

        let props = rsa.crypto_properties.as_ref().unwrap();
        assert_eq!(props.asset_type, "algorithm");

        let alg = props.algorithm_properties.as_ref().unwrap();
        assert_eq!(alg.primitive, "pke");
        assert_eq!(alg.parameter_set_identifier.as_deref(), Some("4096"));
    }

    #[test]
    fn test_false_positive_filtering() {
        let findings = vec![
            Finding {
                file: "/src/Config.java".to_string(),
                line_number: 62,
                line_content: ".requestMatchers(\"/api/v1/crypto/**\").hasAnyRole(ROLE_CRYPTO_USER)".to_string(),
                match_type: "import".to_string(),
                keyword: "crypto".to_string(),
                context: "import".to_string(),
                version: None,
                language: "Go".to_string(),
                source: "import".to_string(),
                category: "library".to_string(),
            },
            Finding {
                file: "/scripts/test.sh".to_string(),
                line_number: 43,
                line_content: "curl -X POST http://localhost:8081/api/v1/crypto/encrypt".to_string(),
                match_type: "import".to_string(),
                keyword: "crypto".to_string(),
                context: "import".to_string(),
                version: None,
                language: "Go".to_string(),
                source: "import".to_string(),
                category: "library".to_string(),
            },
        ];

        let cbom = CbomGenerator::generate_cbom(&findings, None).unwrap();
        assert!(
            cbom.components.is_none(),
            "False positives should be filtered out"
        );
    }

    #[test]
    fn test_java_crypto_extraction() {
        let findings = vec![
            Finding {
                file: "/src/Crypto.java".to_string(),
                line_number: 15,
                line_content: "import javax.crypto.spec.GCMParameterSpec;".to_string(),
                match_type: "import".to_string(),
                keyword: "javax.crypto".to_string(),
                context: "import".to_string(),
                version: None,
                language: "Java".to_string(),
                source: "import".to_string(),
                category: "library".to_string(),
            },
            Finding {
                file: "/src/Crypto.java".to_string(),
                line_number: 20,
                line_content: "javax.crypto.Mac mac = javax.crypto.Mac.getInstance(algorithm);".to_string(),
                match_type: "import".to_string(),
                keyword: "javax.crypto".to_string(),
                context: "import".to_string(),
                version: None,
                language: "Java".to_string(),
                source: "import".to_string(),
                category: "library".to_string(),
            },
        ];

        let cbom = CbomGenerator::generate_cbom(&findings, None).unwrap();
        let components = cbom.components.unwrap();

        let names: Vec<&str> = components.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"AES-GCM"), "Should detect AES-GCM from GCMParameterSpec");
        assert!(names.contains(&"HMAC"), "Should detect HMAC from Mac usage");
    }

    #[test]
    fn test_algorithm_metadata_primitives() {
        let sha = CbomGenerator::get_algorithm_metadata("SHA256");
        assert_eq!(sha.primitive, "hash");

        let rsa = CbomGenerator::get_algorithm_metadata("RSA");
        assert_eq!(rsa.primitive, "pke");

        let aes_gcm = CbomGenerator::get_algorithm_metadata("AES-GCM");
        assert_eq!(aes_gcm.primitive, "ae");
        assert_eq!(aes_gcm.mode.as_deref(), Some("gcm"));

        let hmac = CbomGenerator::get_algorithm_metadata("HMAC-SHA256");
        assert_eq!(hmac.primitive, "mac");
    }

    #[test]
    fn test_json_export() {
        let findings = vec![];
        let cbom = CbomGenerator::generate_cbom(&findings, None).unwrap();
        let json = CbomGenerator::export_json(&cbom).unwrap();

        assert!(json.contains("\"specVersion\""));
        assert!(json.contains("\"1.6\""));
        assert!(json.contains("\"CycloneDX\""));
    }

    #[test]
    fn test_secret_findings() {
        let findings = vec![Finding {
            file: "/scripts/setup.sh".to_string(),
            line_number: 36,
            line_content: "DB_PASSWORD=\"${DB_PASSWORD:-hsm_password}\"".to_string(),
            match_type: "secret".to_string(),
            keyword: "Password".to_string(),
            context: "Hardcoded password".to_string(),
            version: None,
            language: "Shell".to_string(),
            source: "hardcoded".to_string(),
            category: "secret".to_string(),
        }];

        let cbom = CbomGenerator::generate_cbom(&findings, None).unwrap();
        let components = cbom.components.unwrap();
        assert_eq!(components.len(), 1);

        let props = components[0].crypto_properties.as_ref().unwrap();
        assert_eq!(props.asset_type, "related-crypto-material");

        let mat = props.related_crypto_material_properties.as_ref().unwrap();
        assert_eq!(mat.material_type, "password");
    }
}
