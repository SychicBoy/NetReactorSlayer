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
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using de4dot.blocks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using HarmonyLib;
using NETReactorSlayer.Core.Abstractions;
using NETReactorSlayer.Core.Helper;
using Code = dnlib.DotNet.Emit.Code;

namespace NETReactorSlayer.Core.Stages
{
    internal class StringDecrypter : IStage
    {
        public void Run(IContext context)
        {
            Context = context;
            try
            {
                long count;

                try
                {
                    if (Find())
                    {
                        _decryptedResource = _encryptedResource.Decrypt();
                        count = InlineStringsStatically();
                    }
                    else
                        throw new Exception();

                    if (count == 0)
                        throw new Exception();

                    Cleaner.AddMethodToBeRemoved(_encryptedResource.DecrypterMethod);
                    Cleaner.AddResourceToBeRemoved(_encryptedResource.EmbeddedResource);
                }
                catch { count = InlineStringsDynamically(); }


                if (count > 0)
                    Context.Logger.Info(count + " Strings decrypted.");
                else
                    Context.Logger.Warn("Couldn't find any encrypted string.");
            }
            catch (Exception ex)
            {
                Context.Logger.Error($"An unexpected error occurred during decrypting strings. {ex.Message}.");
            }

            _encryptedResource?.Dispose();
        }

        private bool Find()
        {
            foreach (var type in Context.Module.GetTypes())
                try
                {
                    if (type.BaseType != null && type.BaseType.FullName != "System.Object")
                        continue;
                    foreach (var method in from method in type.Methods
                             where method.IsStatic && method.HasBody
                             where DotNetUtils.IsMethod(method, "System.String", "(System.Int32)")
                             where EncryptedResource.IsKnownDecrypter(method, new[] { "System.String" }, true)
                             select method)
                    {
                        FindKeyIv(method);

                        EncryptedResource resource = null;

                        try
                        {
                            resource = new EncryptedResource(Context, method, new[] { "System.String" });
                            if (resource.EmbeddedResource != null)
                            {
                                if (_decrypterMethods.Any(x => x.Value == resource.EmbeddedResource.Name) ||
                                    _decrypterMethods.Count == 0)
                                    _decrypterMethods.Add(resource.DecrypterMethod, resource.EmbeddedResource.Name);

                                if (_encryptedResource == null)
                                    _encryptedResource = resource;
                                else
                                    resource.Dispose();

                                continue;
                            }
                        }
                        catch { }

                        resource?.Dispose();
                    }
                }
                catch { }

            return _decrypterMethods.Count > 0;
        }

        private void FindKeyIv(MethodDef method)
        {
            var requiredTypes = new[]
            {
                "System.Byte[]",
                "System.IO.MemoryStream",
                "System.Security.Cryptography.CryptoStream"
            };
            foreach (var instructions in from calledMethod in DotNetUtils.GetCalledMethods(Context.Module, method)
                     where calledMethod.DeclaringType == method.DeclaringType
                     where calledMethod.MethodSig.GetRetType().GetFullName() == "System.Byte[]"
                     let localTypes = new LocalTypes(calledMethod)
                     where localTypes.All(requiredTypes)
                     select calledMethod.Body.Instructions)
            {
                byte[] newKey = null, newIv = null;
                for (var i = 0; i < instructions.Count && (newKey == null || newIv == null); i++)
                {
                    var instr = instructions[i];
                    if (instr.OpCode.Code != Code.Ldtoken)
                        continue;
                    if (instr.Operand is not FieldDef field)
                        continue;
                    if (field.InitialValue == null)
                        continue;
                    switch (field.InitialValue.Length)
                    {
                        case 32:
                            newKey = field.InitialValue;
                            break;
                        case 16:
                            newIv = field.InitialValue;
                            break;
                    }
                }

                if (newKey == null || newIv == null)
                    continue;

                _stringDecrypterVersion = new LocalTypes(method).Exists("System.IntPtr")
                    ? StringDecrypterVersion.V38
                    : StringDecrypterVersion.V37;

                _key = newKey;
                _iv = newIv;
                return;
            }
        }

        private string Decrypt(int offset)
        {
            if (_key == null)
            {
                var length = BitConverter.ToInt32(_decryptedResource, offset);
                return Encoding.Unicode.GetString(_decryptedResource, offset + 4, length);
            }

            byte[] encryptedStringData;
            switch (_stringDecrypterVersion)
            {
                case StringDecrypterVersion.V37:
                {
                    var fileOffset = BitConverter.ToInt32(_decryptedResource, offset);
                    var length = BitConverter.ToInt32(Context.ModuleBytes, fileOffset);
                    encryptedStringData = new byte[length];
                    Array.Copy(Context.ModuleBytes, fileOffset + 4, encryptedStringData, 0, length);
                    break;
                }
                case StringDecrypterVersion.V38:
                {
                    var rva = BitConverter.ToUInt32(_decryptedResource, offset);
                    var length = Context.PeImage.ReadInt32(rva);
                    encryptedStringData = Context.PeImage.ReadBytes(rva + 4, length);
                    break;
                }
                default:
                    throw new ApplicationException("Unknown string decrypter version");
            }

            return Encoding.Unicode.GetString(DeobUtils.AesDecrypt(encryptedStringData, _key, _iv));
        }

        private long InlineStringsStatically()
        {
            bool IsDecrypterMethod(IMDTokenProvider method) => method != null &&
                                                               _decrypterMethods.Any(x =>
                                                                   x.Key.Equals(method) || x.Key.MDToken.ToInt32()
                                                                       .Equals(method.MDToken.ToInt32()));

            long count = 0;
            foreach (var method in Context.Module.GetTypes().SelectMany(type =>
                         (from x in type.Methods where x.HasBody && x.Body.HasInstructions select x)
                         .ToArray()))
            {
                SimpleDeobfuscator.DeobfuscateBlocks(method);
                for (var i = 0; i < method.Body.Instructions.Count; i++)
                    try
                    {
                        if (!method.Body.Instructions[i].IsLdcI4() ||
                            !method.Body.Instructions[i + 1].OpCode.Equals(OpCodes.Call))
                            continue;

                        var methodDef = ((IMethod)method.Body.Instructions[i + 1].Operand).ResolveMethodDef();
                        if (methodDef != null && methodDef.HasReturnType != true)
                            continue;

                        if (methodDef != null && (!methodDef.HasParams() || methodDef.Parameters.Count != 1 ||
                                                  methodDef.Parameters[0].Type.FullName != "System.Int32"))
                            continue;

                        if (!IsDecrypterMethod(methodDef))
                            continue;

                        var decrypt = Decrypt(method.Body.Instructions[i].GetLdcI4Value());
                        method.Body.Instructions[i].OpCode = OpCodes.Nop;
                        method.Body.Instructions[i + 1].OpCode = OpCodes.Ldstr;
                        method.Body.Instructions[i + 1].Operand = decrypt;
                        count++;
                    }
                    catch { }

                SimpleDeobfuscator.DeobfuscateBlocks(method);
            }

            return count;
        }

        private long InlineStringsDynamically()
        {
            if ((Context.Info.NativeStub && Context.Info.NecroBit) ||
                !Context.Info.UsesReflection)
                return 0;

            long count = 0;
            MethodDef decrypterMethod = null;
            EmbeddedResource encryptedResource = null;

            StacktracePatcher.Patch();
            foreach (var type in Context.Module.GetTypes())
            foreach (var method in (from x in type.Methods where x.HasBody && x.Body.HasInstructions select x)
                     .ToArray())
                for (var i = 0; i < method.Body.Instructions.Count; i++)
                    try
                    {
                        if (!method.Body.Instructions[i].IsLdcI4() ||
                            !method.Body.Instructions[i + 1].OpCode.Equals(OpCodes.Call))
                            continue;

                        var methodDef = ((IMethod)method.Body.Instructions[i + 1].Operand).ResolveMethodDef();
                        if (methodDef is not {HasReturnType: true})
                            continue;

                        if (TypeEqualityComparer.Instance.Equals(method.DeclaringType, methodDef.DeclaringType))
                            continue;

                        if (methodDef.ReturnType.FullName != "System.String" &&
                            !(methodDef.DeclaringType != null &&
                              methodDef.DeclaringType == type &&
                              methodDef.ReturnType.FullName == "System.Object"))
                            continue;

                        if (!methodDef.HasParams() || methodDef.Parameters.Count != 1 ||
                            methodDef.Parameters[0].Type.FullName != "System.Int32")
                            continue;

                        if (!methodDef.Body.Instructions.Any(x =>
                                x.OpCode.Equals(OpCodes.Callvirt) && x.Operand.ToString()!
                                    .Contains("System.Reflection.Assembly::GetManifestResourceStream")))
                            continue;

                        var resourceName = DotNetUtils.GetCodeStrings(methodDef)
                            .FirstOrDefault(name =>
                                Context.Assembly.GetManifestResourceNames().Any(x => x == name));

                        if (resourceName == null)
                            continue;

                        var result = (StacktracePatcher.PatchStackTraceGetMethod.MethodToReplace =
                                Context.Assembly.ManifestModule.ResolveMethod(
                                    (int)methodDef.ResolveMethodDef().MDToken.Raw) as MethodInfo)
                            .Invoke(null, new object[] { method.Body.Instructions[i].GetLdcI4Value() });

                        if (result is not string operand)
                            continue;
                        decrypterMethod ??= methodDef;
                        if (encryptedResource == null &&
                            DotNetUtils.GetResource(Context.Module, resourceName) is EmbeddedResource resource)
                            encryptedResource = resource;
                        method.Body.Instructions[i].OpCode = OpCodes.Nop;
                        method.Body.Instructions[i + 1].OpCode = OpCodes.Ldstr;
                        method.Body.Instructions[i + 1].Operand = operand;
                        count += 1L;
                    }
                    catch { }

            if (decrypterMethod == null || encryptedResource == null)
                return count;
            Cleaner.AddMethodToBeRemoved(decrypterMethod);
            Cleaner.AddResourceToBeRemoved(encryptedResource);

            return count;
        }


        private IContext Context { get; set; }
        private byte[] _key, _iv, _decryptedResource;
        private EncryptedResource _encryptedResource;
        private readonly Dictionary<MethodDef, string> _decrypterMethods = new();
        private StringDecrypterVersion _stringDecrypterVersion;

        private enum StringDecrypterVersion { V37, V38 }

        #region Nested Types

        public class StacktracePatcher
        {
            public static void Patch()
            {
                harmony = new Harmony(HarmonyId);
                harmony.PatchAll(Assembly.GetExecutingAssembly());
            }

            private const string HarmonyId = "_";

            // ReSharper disable once InconsistentNaming
            private static Harmony harmony;

            [HarmonyPatch(typeof(StackFrame), "GetMethod")]
            public class PatchStackTraceGetMethod
            {
                // ReSharper disable once UnusedMember.Global
                // ReSharper disable once InconsistentNaming
                public static void Postfix(ref MethodBase __result)
                {
                    if (__result.DeclaringType != typeof(RuntimeMethodHandle))
                        return;
                    __result = MethodToReplace ?? MethodBase.GetCurrentMethod();
                }

                public static MethodInfo MethodToReplace;
            }
        }

        #endregion
    }
}