using System.Security.Cryptography.X509Certificates;

namespace Winche.Integrity.AppAttest;

/// <summary>
/// Apple App Attestation Root CA (https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem): every
/// App Attest attestation's certificate chain ends here. Valid until 15 March 2045.
/// </summary>
public static class AppleAppAttestRoot
{
    /// <summary>Its SHA-256 fingerprint, checked when it's loaded.</summary>
    public const string Sha256 = "1CB9823BA28BA6AD2D33A006941DE2AE4F513EF1D4E831B9F7E0FA7B6242C932";

    private const string Der = "MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNaFw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlvbiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdhNbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9auYen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijVoyFraWVIyd/dganmrduC1bmTBGwD";

    /// <summary>The certificate.</summary>
    public static X509Certificate2 Certificate { get; } = Load();

    private static X509Certificate2 Load()
    {
        var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(Der));
        if (!string.Equals(cert.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256), Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The embedded Apple App Attestation Root CA isn't the one expected.");
        return cert;
    }
}
