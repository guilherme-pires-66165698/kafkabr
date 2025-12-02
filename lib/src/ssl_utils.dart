part of kafka;

/// Utilities for SSL/TLS support in Kafka connections
class KafkaSSLConfig {
  /// Enable SSL/TLS connections
  final bool enabled;

  /// Security context containing certificates
  final SecurityContext? securityContext;

  /// Callback to validate server certificates
  final bool Function(X509Certificate)? onBadCertificate;

  const KafkaSSLConfig({
    this.enabled = false,
    this.securityContext,
    this.onBadCertificate,
  });

  /// Creates an SSL config with default strict certificate validation
  factory KafkaSSLConfig.withContext(SecurityContext context) {
    return KafkaSSLConfig(
      enabled: true,
      securityContext: context,
      onBadCertificate: _defaultBadCertificateHandler,
    );
  }

  /// Default certificate validation (strict - rejects all bad certificates)
  static bool _defaultBadCertificateHandler(X509Certificate cert) {
    // Strict validation - do not accept invalid certificates
    return false;
  }
}

/// Helper function to create SecurityContext from certificate bytes
SecurityContext createSecurityContextFromBytes({
  required List<int> certificateBytes,
  String? password,
}) {
  final context = SecurityContext(withTrustedRoots: true);

  try {
    // Load the certificate chain (includes client cert)
    context.useCertificateChainBytes(certificateBytes, password: password);

    // Load the private key
    context.usePrivateKeyBytes(certificateBytes, password: password);

    // Load trusted certificates (CA chain)
    context.setTrustedCertificatesBytes(certificateBytes, password: password);

  } catch (e) {
    throw ArgumentError('Failed to load certificate: $e');
  }

  return context;
}
