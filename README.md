# ABPPack.cs
ABPPack C# implementation.

## Install
 * Package Manager: `Install-Package ABPPack`
 * .NET CLI: `dotnet add package ABPPack`
 * PackageReference: `<PackageReference Include="ABPPack" Version="0.0.1" />`
 * Paket CLI: `paket add ABPPack`

## Usage
```cs
using System; // Console
using System.Text; // Encoding
using System.IO; // File
using Org.BouncyCastle.Crypto.Parameters; // RsaKeyParameters

void Example()
{
#region Keys
    // Generate AES key
    var aesKey = ABPAES.MakeKey();

    // Import RSA keypair from .pem file
    var rsaKeypair = ABPRSA.MakeKeys(File.ReadAllText("keypair.pem"));
    var rsaKeyprv = (RsaKeyParameters)rsaKeypair.Private;
    var rsaKeypub = (RsaKeyParameters)rsaKeypair.Public;
#endregion

#region Selftest
    // These will complain on stderr and return false if something goes wrong.
    ABPRSA.SelfTest(rsaKeypair);
    ABPAES.SelfTest(aesKey);
    ABPHPack.SelfTest(rsaKeypair);
    ABPPack.SelfTest(aesKey);
#endregion

    var testBuffer = Encoding.UTF8.GetBytes("Hello World!"); // Test buffer for test message

#region ABPHPack
    var hPack = new ABPHPack { data = testBuffer }; // Create a Handshake Pack
    var hBytes = hPack.Pack(rsaKeypub); // Encrypt & Assemble a Handshake Pack
    var hPack2 = new ABPHPack(hBytes, rsaKeyprv); // Take apart & Decrypt a Handshake Pack
    Console.WriteLine($"ABPHPack: {Encoding.UTF8.GetString(hPack2.data)}"); // "Hello World!"
#endregion

#region ABPHPack
    var pack = new ABPPack { data = testBuffer }; // Create a Handshake Pack
    var bytes = pack.Pack(aesKey); // Encrypt & Assemble a Handshake Pack
    var pack2 = new ABPPack(bytes, aesKey); // Take apart & Decrypt a Handshake Pack
    Console.WriteLine($"ABPPack: {Encoding.UTF8.GetString(pack2.data)}"); // "Hello World!"
#endregion
}
```