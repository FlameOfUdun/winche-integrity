using System.Formats.Asn1;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Winche.Integrity.AppAttest;

namespace Winche.Integrity.Tests;

/// <summary>
/// App Attest as a device and Apple make it, with a root of the test's own: a device key, its attestation (the
/// credential certificate carrying the nonce, issued through an intermediate) and assertions signed with it.
/// </summary>
public sealed class FakeAppAttest : IDisposable
{
    public X509Certificate2 Root { get; }
    private readonly X509Certificate2 _intermediate;
    private readonly ECDsa _intermediateKey;
    public ECDsa DeviceKey { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public byte[] PublicPoint { get; }
    public string KeyId { get; }

    public FakeAppAttest()
    {
        var now = DateTimeOffset.UtcNow;
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var rootReq = new CertificateRequest("CN=Test App Attestation Root CA", rootKey, HashAlgorithmName.SHA384);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        using var rootWithKey = rootReq.CreateSelfSigned(now.AddDays(-1), now.AddYears(5));
        Root = X509CertificateLoader.LoadCertificate(rootWithKey.RawData);

        _intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var interReq = new CertificateRequest("CN=Test App Attestation CA 1", _intermediateKey, HashAlgorithmName.SHA384);
        interReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        interReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        _intermediate = interReq.Create(rootWithKey, now.AddDays(-1), now.AddYears(1), [1, 2, 3, 4]);

        var p = DeviceKey.ExportParameters(false);
        PublicPoint = [0x04, .. p.Q.X!, .. p.Q.Y!];
        KeyId = Convert.ToBase64String(SHA256.HashData(PublicPoint));
    }

    public static byte[] ClientDataHash(string challenge) => SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(challenge));

    /// <summary>An attestation of the device key for <paramref name="clientDataHash"/>; parts can be spoiled to test refusals.</summary>
    public byte[] Attest(byte[] clientDataHash, string teamId, string bundleId, bool development = false, uint counter = 0,
        byte[]? nonceOverride = null, string? credentialKeyId = null, bool selfIssued = false)
    {
        var keyIdBytes = Convert.FromBase64String(credentialKeyId ?? KeyId);
        byte[] aaguid = development ? "appattestdevelop"u8.ToArray() : [.. "appattest"u8, 0, 0, 0, 0, 0, 0, 0];
        var authData = new List<byte>(AppAttestVerifier.RpIdHash(teamId, bundleId)) { 0x40 };
        authData.AddRange(BigEndian(counter));
        authData.AddRange(aaguid);
        authData.AddRange([(byte)(keyIdBytes.Length >> 8), (byte)keyIdBytes.Length]);
        authData.AddRange(keyIdBytes);
        var nonce = nonceOverride ?? SHA256.HashData([.. authData, .. clientDataHash]);

        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        using (w.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1)))
            w.WriteOctetString(nonce);
        var leafReq = new CertificateRequest("CN=" + Convert.ToHexString(SHA256.HashData(PublicPoint))[..16], DeviceKey, HashAlgorithmName.SHA256);
        leafReq.CertificateExtensions.Add(new X509Extension("1.2.840.113635.100.8.2", w.Encode(), false));
        var now = DateTimeOffset.UtcNow;
        X509Certificate2 leaf;
        if (selfIssued)
            leaf = leafReq.CreateSelfSigned(now.AddDays(-1), now.AddDays(3));
        else
        {
            using var issuer = _intermediate.CopyWithPrivateKey(_intermediateKey);
            leaf = leafReq.Create(issuer, now.AddDays(-1), now.AddDays(3), RandomNumberGenerator.GetBytes(8));
        }

        var cbor = new CborWriter();
        cbor.WriteStartMap(3);
        cbor.WriteTextString("fmt"); cbor.WriteTextString("apple-appattest");
        cbor.WriteTextString("attStmt");
        cbor.WriteStartMap(2);
        cbor.WriteTextString("x5c");
        cbor.WriteStartArray(2); cbor.WriteByteString(leaf.RawData); cbor.WriteByteString(_intermediate.RawData); cbor.WriteEndArray();
        cbor.WriteTextString("receipt"); cbor.WriteByteString("receipt"u8);
        cbor.WriteEndMap();
        cbor.WriteTextString("authData"); cbor.WriteByteString([.. authData]);
        cbor.WriteEndMap();
        leaf.Dispose();
        return cbor.Encode();
    }

    /// <summary>An assertion for <paramref name="clientDataHash"/> with the counter at <paramref name="counter"/>.</summary>
    public byte[] Assert(byte[] clientDataHash, string teamId, string bundleId, uint counter, ECDsa? signWith = null)
    {
        byte[] authData = [.. AppAttestVerifier.RpIdHash(teamId, bundleId), 0x00, .. BigEndian(counter)];
        var signature = (signWith ?? DeviceKey).SignData(SHA256.HashData([.. authData, .. clientDataHash]), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        var cbor = new CborWriter();
        cbor.WriteStartMap(2);
        cbor.WriteTextString("signature"); cbor.WriteByteString(signature);
        cbor.WriteTextString("authenticatorData"); cbor.WriteByteString(authData);
        cbor.WriteEndMap();
        return cbor.Encode();
    }

    private static byte[] BigEndian(uint v) => [(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v];

    public void Dispose()
    {
        DeviceKey.Dispose();
        _intermediateKey.Dispose();
        _intermediate.Dispose();
        Root.Dispose();
    }
}
