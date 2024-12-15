using System.Collections.Generic;
using System.Linq;
using de4dot.blocks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

namespace NETReactorSlayer.Core.Helper;

internal partial class EncryptedResource
{
    private class DecrypterV1 : IDecrypter
    {
        public DecrypterV1(MethodDef method)
        {
            _key = GetDecryptionKey(method);
            _iv = GetDecryptionIV(method);
        }

        public static bool CouldBeResourceDecrypter(MethodDef method, StringCounts stringCounts,
            IEnumerable<string> additionalTypes)
        {
            var requiredTypes = new[]
            {
                new List<string>
                {
                    "System.Byte[]",
                    "System.Security.Cryptography.CryptoStream",
                    "System.Security.Cryptography.ICryptoTransform",
                    "System.String",
                    "System.Boolean"
                },
                new List<string>
                {
                    "System.Security.Cryptography.ICryptoTransform",
                    "System.IO.Stream",
                    "System.Int32",
                    "System.Byte[]",
                    "System.Boolean"
                },
                new List<string>
                {
                    "System.Security.Cryptography.ICryptoTransform",
                    "System.Int32",
                    "System.Byte[]",
                    "System.Boolean"
                }
            };
            requiredTypes[0].AddRange(additionalTypes);

            if (stringCounts.All(requiredTypes[0]) ||
                stringCounts.All(requiredTypes[1]) ||
                (stringCounts.All(requiredTypes[2]) && method.Body.Instructions.Any(x =>
                    x.OpCode.Equals(OpCodes.Newobj) && x.Operand != null && x.Operand.ToString()!
                        .Contains("System.Security.Cryptography.CryptoStream::.ctor"))))
                return DotNetUtils.GetMethod(method.DeclaringType,
                    "System.Security.Cryptography.SymmetricAlgorithm",
                    "()") == null || (!stringCounts.Exists("System.UInt64") &&
                                      (!stringCounts.Exists("System.UInt32") ||
                                       stringCounts.Exists("System.Reflection.Assembly")));

            return false;
        }

        public byte[] Decrypt(EmbeddedResource resource) =>
            DeobUtils.AesDecrypt(resource.CreateReader().ToArray(), _key, _iv);


        private readonly byte[] _key, _iv;
    }
}