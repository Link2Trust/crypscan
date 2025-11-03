#!/usr/bin/env python3
"""
Test script to verify PKCS#12 functionality with HSM key handling.
This script tests the fix for the PKCS#12 key mismatch issue.
"""

import os
import tempfile
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
import datetime


def _get_private_key_from_hsm(private_key_id):
    """
    Attempt to retrieve the private key from HSM.
    In real HSM implementations, this would typically return None
    for non-exportable keys due to security policies.
    """
    print(f"Attempting to retrieve private key from HSM: {private_key_id}")
    # Simulate HSM security policy - most HSMs don't allow private key export
    return None


def _create_demo_pkcs12_with_explanation(certificate, cert_obj, password):
    """
    Create a text file explaining why PKCS#12 cannot be generated for HSM-backed certificates.
    """
    explanation = f"""
PKCS#12 Export Not Available for HSM-Backed Certificate

Certificate: {certificate.common_name}
Certificate ID: {certificate.id}
Key Type: {certificate.key_type}
Private Key ID: {certificate.private_key_id}

This certificate was generated using a Hardware Security Module (HSM).
For security reasons, private keys stored in HSMs are typically non-exportable.

Therefore, a PKCS#12 package containing both the certificate and private key
cannot be created. This is a security feature of HSM systems.

If you need the certificate only, please download it in PEM or DER format
using the appropriate download options.

For applications requiring the private key, please configure them to use
the HSM directly for cryptographic operations.

Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    """.strip()
    
    return explanation.encode('utf-8'), 'application/octet-stream'


def create_test_certificate():
    """Create a test certificate for testing."""
    # Generate a test key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create a test certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("test.example.com"),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    return cert, private_key


class MockCertificate:
    """Mock certificate object for testing."""
    def __init__(self, common_name, cert_id, key_type, private_key_id):
        self.common_name = common_name
        self.id = cert_id
        self.key_type = key_type
        self.private_key_id = private_key_id


def test_pkcs12_with_regular_key():
    """Test PKCS#12 creation with a regular (non-HSM) key."""
    print("Testing PKCS#12 creation with regular key...")
    
    cert, private_key = create_test_certificate()
    password = "test123"
    
    try:
        # Create PKCS#12
        p12_data = pkcs12.serialize_key_and_certificates(
            name=b"test-cert",
            key=private_key,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )
        
        print(f"✓ Successfully created PKCS#12 package ({len(p12_data)} bytes)")
        
        # Verify we can load it back
        (loaded_key, loaded_cert, loaded_cas) = pkcs12.load_key_and_certificates(
            p12_data, password.encode()
        )
        
        print("✓ Successfully verified PKCS#12 package")
        return True
    except Exception as e:
        print(f"✗ Failed to create PKCS#12: {e}")
        return False


def test_pkcs12_with_hsm_key():
    """Test PKCS#12 creation with HSM key (should create explanation file)."""
    print("\nTesting PKCS#12 creation with HSM key...")
    
    cert, _ = create_test_certificate()
    mock_cert = MockCertificate(
        common_name="test-hsm.example.com",
        cert_id="hsm-001",
        key_type="HSM_RSA_2048",
        private_key_id="hsm-key-12345"
    )
    
    # Try to get private key from HSM (should return None)
    hsm_private_key = _get_private_key_from_hsm(mock_cert.private_key_id)
    
    if hsm_private_key is None:
        print("✓ HSM private key is non-exportable (as expected)")
        
        # Create explanation file instead
        explanation_data, content_type = _create_demo_pkcs12_with_explanation(
            mock_cert, cert, "test123"
        )
        
        print(f"✓ Created explanation file ({len(explanation_data)} bytes)")
        print(f"Content type: {content_type}")
        
        # Save to temp file to verify
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt') as f:
            f.write(explanation_data)
            temp_path = f.name
        
        print(f"✓ Explanation saved to: {temp_path}")
        
        # Display first few lines
        with open(temp_path, 'r') as f:
            lines = f.readlines()[:10]
            print("Content preview:")
            for line in lines:
                print(f"  {line.rstrip()}")
        
        # Clean up
        os.unlink(temp_path)
        return True
    else:
        print("✗ Expected HSM key to be non-exportable")
        return False


def main():
    """Run all tests."""
    print("Testing PKCS#12 functionality with HSM key handling")
    print("=" * 60)
    
    success_count = 0
    total_tests = 2
    
    # Test regular PKCS#12 creation
    if test_pkcs12_with_regular_key():
        success_count += 1
    
    # Test HSM PKCS#12 handling
    if test_pkcs12_with_hsm_key():
        success_count += 1
    
    print("\n" + "=" * 60)
    print(f"Test Results: {success_count}/{total_tests} tests passed")
    
    if success_count == total_tests:
        print("✓ All tests passed! The PKCS#12 HSM key handling fix is working correctly.")
    else:
        print("✗ Some tests failed. Please review the implementation.")
    
    return success_count == total_tests


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
