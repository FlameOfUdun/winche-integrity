using System.Formats.Asn1;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Winche.Integrity.AppAttest;

/// <summary>Why an App Attest attestation or assertion was refused: a short reason and a sentence.</summary>
public sealed class AppAttestException(string reason, string message) : Exception(message)
{
    /// <summary>A short reason, e.g. <c>chain</c>, <c>nonce</c>, <c>app</c>, <c>counter</c>, <c>signature</c>.</summary>
    public string Reason { get; } = reason;
}

/// <summary>A key App Attest vouched for: its public key (an uncompressed P-256 point) and the environment.</summary>
/// <param name="Development">Made by a development build (<c>appattestdevelop</c>), not one from TestFlight or the App Store.</param>
/// <param name="Receipt">Apple's receipt, kept for fraud checks later.</param>
public sealed record AttestedKey(byte[] PublicKey, bool Development, byte[] Receipt);

/// <summary>
/// Checks App Attest attestations (a device's new key, once) and assertions (each later proof, signed with that key),
/// as Apple describes in "Validating apps that connect to your server".
/// </summary>
public sealed class AppAttestVerifier(X509Certificate2? root = null, TimeProvider? time = null)
{
    private const string NonceOid = "1.2.840.113635.100.8.2";
    private static readonly byte[] Development = "appattestdevelop"u8.ToArray();
    private static readonly byte[] Production = [.. "appattest"u8, 0, 0, 0, 0, 0, 0, 0];

    private readonly X509Certificate2 _root = root ?? AppleAppAttestRoot.Certificate;
    private readonly TimeProvider _time = time ?? TimeProvider.System;

    /// <summary>The App ID App Attest signs for: <c>TEAMID.bundle.id</c>.</summary>
    public static byte[] RpIdHash(string teamId, string bundleId) => SHA256.HashData(Encoding.UTF8.GetBytes($"{teamId}.{bundleId}"));

    /// <summary>
    /// Checks the attestation of <paramref name="keyId"/> (the key's id, base64, as the device gives it) made for
    /// <paramref name="clientDataHash"/>, for the app <paramref name="teamId"/>.<paramref name="bundleId"/>.
    /// </summary>
    public AttestedKey VerifyAttestation(byte[] attestation, byte[] clientDataHash, string keyId, string teamId, string bundleId, bool allowDevelopment)
    {
        byte[] keyIdBytes;
        try { keyIdBytes = Convert.FromBase64String(keyId); }
        catch (FormatException) { throw new AppAttestException("key", "The key id isn't base64."); }

        // { fmt: "apple-appattest", attStmt: { x5c: [credCert, intermediate], receipt }, authData }
        string? fmt = null; byte[]? authData = null, receipt = null; List<byte[]> x5c = [];
        try
        {
            var r = new CborReader(attestation, CborConformanceMode.Lax);
            var n = r.ReadStartMap();
            for (var i = 0; n is null ? r.PeekState() != CborReaderState.EndMap : i < n; i++)
            {
                switch (r.ReadTextString())
                {
                    case "fmt": fmt = r.ReadTextString(); break;
                    case "authData": authData = r.ReadByteString(); break;
                    case "attStmt":
                        var m = r.ReadStartMap();
                        for (var j = 0; m is null ? r.PeekState() != CborReaderState.EndMap : j < m; j++)
                        {
                            switch (r.ReadTextString())
                            {
                                case "x5c":
                                    var c = r.ReadStartArray();
                                    for (var k = 0; c is null ? r.PeekState() != CborReaderState.EndArray : k < c; k++) x5c.Add(r.ReadByteString());
                                    r.ReadEndArray();
                                    break;
                                case "receipt": receipt = r.ReadByteString(); break;
                                default: r.SkipValue(); break;
                            }
                        }
                        r.ReadEndMap();
                        break;
                    default: r.SkipValue(); break;
                }
            }
            r.ReadEndMap();
        }
        catch (Exception e) when (e is CborContentException or InvalidOperationException or FormatException)
        {
            throw new AppAttestException("format", "The attestation isn't App Attest's (it can't be read).");
        }
        if (fmt != "apple-appattest" || authData is null || x5c.Count < 2)
            throw new AppAttestException("format", "The attestation isn't App Attest's (apple-appattest with two certificates).");

        // 1. The credential certificate chains to Apple's root through the intermediate.
        using var cred = Load(x5c[0]);
        using var intermediate = Load(x5c[1]);
        using (var chain = new X509Chain())
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(_root);
            chain.ChainPolicy.ExtraStore.Add(intermediate);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationTime = _time.GetUtcNow().UtcDateTime;
            chain.ChainPolicy.VerificationTimeIgnored = false;
            if (!chain.Build(cred) || chain.ChainElements.Count != 3 || !chain.ChainElements[^1].Certificate.RawData.AsSpan().SequenceEqual(_root.RawData))
                throw new AppAttestException("chain", "The attestation's certificates don't lead to Apple's App Attestation root.");
        }

        // 2-3. nonce = SHA256(authData || clientDataHash), in the credential certificate's extension.
        var nonce = SHA256.HashData([.. authData, .. clientDataHash]);
        if (cred.Extensions[NonceOid] is not { } ext || !NonceOf(ext.RawData).AsSpan().SequenceEqual(nonce))
            throw new AppAttestException("nonce", "The attestation wasn't made for this challenge.");

        // 4. The key id is the SHA-256 of the key's public point.
        var publicKey = PublicPoint(cred);
        if (!SHA256.HashData(publicKey).AsSpan().SequenceEqual(keyIdBytes))
            throw new AppAttestException("key", "The attestation is for another key.");

        // 5-8. The app, a counter of 0, the environment, and the credential id.
        var a = AuthData.Read(authData, attested: true);
        if (!a.RpIdHash.SequenceEqual(RpIdHash(teamId, bundleId)))
            throw new AppAttestException("app", $"The attestation is for another app than {teamId}.{bundleId}.");
        if (a.Counter != 0) throw new AppAttestException("counter", "A new key's counter isn't 0.");
        var development = a.Aaguid.SequenceEqual(Development);
        if (!development && !a.Aaguid.SequenceEqual(Production)) throw new AppAttestException("environment", "The attestation is from neither App Attest environment.");
        if (development && !allowDevelopment) throw new AppAttestException("environment", "The attestation is from a development build, which this app doesn't accept (turn on development builds for it).");
        if (!a.CredentialId.SequenceEqual(keyIdBytes)) throw new AppAttestException("key", "The attestation's credential isn't the key.");
        return new AttestedKey(publicKey, development, receipt ?? []);
    }

    /// <summary>
    /// Checks an assertion made with the key whose public point is <paramref name="publicKey"/>, for
    /// <paramref name="clientDataHash"/>; the key's new counter, which must be above <paramref name="lastCounter"/>.
    /// </summary>
    public uint VerifyAssertion(byte[] assertion, byte[] clientDataHash, byte[] publicKey, string teamId, string bundleId, uint lastCounter)
    {
        byte[]? signature = null, authData = null;
        try
        {
            var r = new CborReader(assertion, CborConformanceMode.Lax);
            var n = r.ReadStartMap();
            for (var i = 0; n is null ? r.PeekState() != CborReaderState.EndMap : i < n; i++)
            {
                switch (r.ReadTextString())
                {
                    case "signature": signature = r.ReadByteString(); break;
                    case "authenticatorData": authData = r.ReadByteString(); break;
                    default: r.SkipValue(); break;
                }
            }
            r.ReadEndMap();
        }
        catch (Exception e) when (e is CborContentException or InvalidOperationException or FormatException)
        {
            throw new AppAttestException("format", "The assertion isn't App Attest's (it can't be read).");
        }
        if (signature is null || authData is null) throw new AppAttestException("format", "The assertion has no signature or authenticator data.");

        var nonce = SHA256.HashData([.. authData, .. clientDataHash]);
        using var key = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = publicKey[1..33], Y = publicKey[33..65] },
        });
        if (!key.VerifyData(nonce, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
            throw new AppAttestException("signature", "The assertion isn't signed by the device's key.");
        var a = AuthData.Read(authData, attested: false);
        if (!a.RpIdHash.SequenceEqual(RpIdHash(teamId, bundleId)))
            throw new AppAttestException("app", $"The assertion is for another app than {teamId}.{bundleId}.");
        if (a.Counter <= lastCounter) throw new AppAttestException("counter", "The assertion's counter didn't go up: it was used before.");
        return a.Counter;
    }

    private static X509Certificate2 Load(byte[] der)
    {
        try { return X509CertificateLoader.LoadCertificate(der); }
        catch (CryptographicException) { throw new AppAttestException("chain", "A certificate in the attestation can't be read."); }
    }

    /// <summary>SEQUENCE { [1] EXPLICIT OCTET STRING nonce }.</summary>
    private static byte[] NonceOf(byte[] extension)
    {
        try
        {
            var seq = new AsnReader(extension, AsnEncodingRules.DER).ReadSequence();
            var tagged = seq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1));
            return tagged.ReadOctetString();
        }
        catch (AsnContentException) { return []; }
    }

    /// <summary>The key's public point, uncompressed: 0x04 ‖ X ‖ Y (65 bytes).</summary>
    private static byte[] PublicPoint(X509Certificate2 cert)
    {
        using var key = cert.GetECDsaPublicKey() ?? throw new AppAttestException("key", "The credential certificate has no P-256 key.");
        var p = key.ExportParameters(false);
        if (p.Q.X is not { Length: 32 } x || p.Q.Y is not { Length: 32 } y) throw new AppAttestException("key", "The credential certificate's key isn't P-256.");
        return [0x04, .. x, .. y];
    }

    /// <summary>rpIdHash (32) ‖ flags (1) ‖ counter (4, big-endian) [‖ aaguid (16) ‖ credential id length (2) ‖ id ‖ key].</summary>
    private sealed record AuthData(byte[] RpIdHash, uint Counter, byte[] Aaguid, byte[] CredentialId)
    {
        public static AuthData Read(byte[] d, bool attested)
        {
            if (d.Length < 37 || (attested && d.Length < 55)) throw new AppAttestException("format", "The authenticator data is too short.");
            var counter = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(33, 4));
            if (!attested) return new(d[..32], counter, [], []);
            var length = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(53, 2));
            if (d.Length < 55 + length) throw new AppAttestException("format", "The authenticator data is cut short.");
            return new(d[..32], counter, d[37..53], d[55..(55 + length)]);
        }
    }
}
