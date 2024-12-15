/*
    Copyright (C) 2021 CodeStrikers.org
    This file is part of NETReactorSlayer.
    NETReactorSlayer is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    NETReactorSlayer is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with NETReactorSlayer.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Linq;
using de4dot.blocks;
using de4dot.blocks.cflow;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NETReactorSlayer.Core.Abstractions;

namespace NETReactorSlayer.Core.Helper
{
    internal partial class EncryptedResource : IDisposable
    {
        public EncryptedResource(IContext context, MethodDef method, IList<string> additionalTypes)
        {
            SimpleDeobfuscator.Deobfuscate(method);
            DecrypterMethod = method;
            AdditionalTypes = additionalTypes;
            Decrypter = GetDecrypter();
            EmbeddedResource = GetEncryptedResource(context);
        }

        public EncryptedResource(IContext context, MethodDef method)
        {
            SimpleDeobfuscator.Deobfuscate(method);
            DecrypterMethod = method;
            AdditionalTypes = Array.Empty<string>();
            Decrypter = GetDecrypter();
            EmbeddedResource = GetEncryptedResource(context);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposing)
                return;
            EmbeddedResource = null;
            Decrypter = null;
        }

        public byte[] Decrypt() => Decrypter.Decrypt(EmbeddedResource);

        private EmbeddedResource GetEncryptedResource(IContext context)
        {
            if (!DecrypterMethod.HasBody || !DecrypterMethod.Body.HasInstructions)
                return null;

            foreach (var s in DotNetUtils.GetCodeStrings(DecrypterMethod))
                if (DotNetUtils.GetResource(context.Module, s) is EmbeddedResource resource)
                    return resource;

            return null;
        }

        private IDecrypter GetDecrypter()
        {
            if (!DecrypterMethod.IsStatic || !DecrypterMethod.HasBody)
                return null;

            var localTypes = new LocalTypes(DecrypterMethod);

            if (DecrypterV1.CouldBeResourceDecrypter(DecrypterMethod, localTypes, AdditionalTypes))
                return new DecrypterV1(DecrypterMethod);

            if (DecrypterV3.CouldBeResourceDecrypter(localTypes, AdditionalTypes))
                return new DecrypterV3(DecrypterMethod);

            if (DecrypterV4.CouldBeResourceDecrypter(DecrypterMethod, localTypes, AdditionalTypes))
                return new DecrypterV4(DecrypterMethod);

            return DecrypterV2.CouldBeResourceDecrypter(localTypes, AdditionalTypes)
                ? new DecrypterV2(DecrypterMethod)
                : null;
        }

        public static bool IsKnownDecrypter(MethodDef method, IList<string> additionalTypes, bool checkResource)
        {
            SimpleDeobfuscator.Deobfuscate(method);
            if (checkResource)
            {
                if (!method.HasBody || !method.Body.HasInstructions)
                    return false;

                if (!DotNetUtils.GetCodeStrings(method)
                        .Any(x => DotNetUtils.GetResource(method.Module, x) is EmbeddedResource))
                    return false;
            }

            if (!method.IsStatic || !method.HasBody)
                return false;

            var localTypes = new LocalTypes(method);
            if (DecrypterV1.CouldBeResourceDecrypter(method, localTypes, additionalTypes))
                return true;

            if (DecrypterV3.CouldBeResourceDecrypter(localTypes, additionalTypes))
                return true;

            return DecrypterV4.CouldBeResourceDecrypter(method, localTypes, additionalTypes) ||
                   DecrypterV2.CouldBeResourceDecrypter(localTypes, additionalTypes);
        }

        private static byte[] GetDecryptionKey(MethodDef method) => ArrayFinder.GetInitializedByteArray(method, 32);

        private static byte[] GetDecryptionIV(MethodDef method)
        {
            var bytes = ArrayFinder.GetInitializedByteArray(method, 16);

            if (CallsMethodContains(method, "System.Array::Reverse"))
                Array.Reverse(bytes);

            if (!UsesPublicKeyToken(method))
                return bytes;

            if (method.Module.Assembly.PublicKeyToken is not { } publicKeyToken ||
                publicKeyToken.Data.Length == 0)
                return bytes;

            for (var i = 0; i < 8; i++)
                bytes[i * 2 + 1] = publicKeyToken.Data[i];

            return bytes;
        }

        private static bool UsesPublicKeyToken(MethodDef method)
        {
            int[] indexes = { 1, 0, 3, 1, 5, 2, 7, 3, 9, 4, 11, 5, 13, 6, 15, 7 };
            var index = 0;
            foreach (var instr in method.Body.Instructions)
                if (instr.OpCode.FlowControl != FlowControl.Next)
                    index = 0;
                else if (instr.IsLdcI4())
                {
                    if (instr.GetLdcI4Value() != indexes[index++])
                        index = 0;
                    else if (index >= indexes.Length)
                        return true;
                }

            return false;
        }

        private static bool CallsMethodContains(MethodDef method, string fullName)
        {
            if (method?.Body == null)
                return false;

            return (from instr in method.Body.Instructions
                    where instr.OpCode.Code is Code.Call or Code.Callvirt or Code.Newobj
                    select instr.Operand).OfType<IMethod>()
                .Any(calledMethod => calledMethod.FullName.Contains(fullName));
        }

        public static bool TryGetLdcValue(Instruction instruction, out int value)
        {
            value = 0;

            if (!instruction.IsLdcI4() &&
                !instruction.OpCode.Equals(OpCodes.Ldc_I8) &&
                !instruction.OpCode.Equals(OpCodes.Ldc_R4) &&
                !instruction.OpCode.Equals(OpCodes.Ldc_R8))
                return false;

            try
            {
                value = instruction.IsLdcI4() ?
                    instruction.GetLdcI4Value() :
                    Convert.ToInt32(instruction.Operand);

                return true;
            }
            catch
            {
                return false;
            }
        }

        public MethodDef DecrypterMethod { get; }
        public EmbeddedResource EmbeddedResource { get; private set; }
        private IList<string> AdditionalTypes { get; }
        private IDecrypter Decrypter { get; set; }

        public enum DecrypterVersion { V69, V6X }

        private interface IDecrypter
        {
            byte[] Decrypt(EmbeddedResource resource);
        }
        
    }
}