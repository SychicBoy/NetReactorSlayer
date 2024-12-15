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
using System.IO;
using System.Linq;
using de4dot.blocks;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.IO;
using NETReactorSlayer.Core.Abstractions;
using NETReactorSlayer.Core.Helper;

namespace NETReactorSlayer.Core.Stages
{
    internal class MethodDecrypter : IStage
    {
        public void Run(IContext context)
        {
            Context = context;
            try
            {
                if (!Find() && !Find2())
                {
                    Context.Logger.Warn("Couldn't find any encrypted method.");
                    return;
                }

                Context.Info.NecroBit = true;

                var bytes = _encryptedResource.Decrypt();

                if (!RestoreMethodsBody(bytes))
                    throw new InvalidOperationException();

                Cleaner.AddResourceToBeRemoved(_encryptedResource.EmbeddedResource);
                Cleaner.AddCallToBeRemoved(_encryptedResource.DecrypterMethod);
                Context.Logger.Info(
                    $"{Context.Module.GetTypes().SelectMany(x => x.Methods).Count()} Methods decrypted.");
            }
            catch (Exception ex)
            {
                Context.Logger.Error($"An unexpected error occurred during decrypting methods. {ex.Message}.");
            }

            _encryptedResource?.Dispose();
        }

        private bool Find()
        {
            foreach (var methodDef in Context.Module.GetTypes().SelectMany(type => (from method in type.Methods.ToList()
                         where DotNetUtils.IsMethod(method, "System.UInt32",
                                   "(System.IntPtr,System.IntPtr,System.IntPtr,System.UInt32,System.IntPtr,System.UInt32&)") ||
                               DotNetUtils.IsMethod(method, "System.UInt32",
                                   "(System.UInt64&,System.IntPtr,System.IntPtr,System.UInt32,System.IntPtr&,System.UInt32&)")
                         from methodDef in from x in method.DeclaringType.Methods
                             where x.IsStatic && x.HasBody && x.Body.HasInstructions
                             select x
                         from call in DotNetUtils.GetMethodCalls(methodDef)
                         where call.MDToken.ToInt32() == method.MDToken.ToInt32()
                         select methodDef).Where(methodDef =>
                         EncryptedResource.IsKnownDecrypter(methodDef, Array.Empty<string>(), true))))
            {
                _encryptedResource = new EncryptedResource(Context, methodDef);
                if (_encryptedResource.EmbeddedResource != null)
                    return true;
                _encryptedResource.Dispose();
            }

            return false;
        }

        private bool Find2()
        {
            var staticConstructors = new[]
            {
                Context.Module.EntryPoint?.DeclaringType?.FindStaticConstructor(),
                Context.Module.GlobalType.FindStaticConstructor()
            };

            foreach (var cctor in staticConstructors)
            {
                if (cctor is not { HasBody: true } || !cctor.Body.HasInstructions)
                    return false;
                foreach (var instr in cctor.Body.Instructions.Where(instr => instr.OpCode.Equals(OpCodes.Call)))
                    if (instr.Operand is MethodDef { DeclaringType: not null, HasBody: true } methodDef &&
                        methodDef.Body.HasInstructions)
                        if (DotNetUtils.GetMethod(methodDef.DeclaringType,
                                "System.Security.Cryptography.SymmetricAlgorithm", "()") != null)
                        {
                            if (!EncryptedResource.IsKnownDecrypter(methodDef, Array.Empty<string>(), true))
                                continue;

                            _encryptedResource = new EncryptedResource(Context, methodDef);
                            if (_encryptedResource.EmbeddedResource != null)
                                return true;
                            _encryptedResource.Dispose();
                        }
            }

            return false;
        }

        private bool FindBinaryReaderMethod(out int popCallsCount)
        {
            popCallsCount = 0;
            var decrypterMethod = _encryptedResource.DecrypterMethod;
            var calls = decrypterMethod.Body.Instructions
                .Where(x => x.OpCode.Equals(OpCodes.Callvirt) && x.Operand is MethodDef).Select(x => x.Operand)
                .Cast<MethodDef>();
            foreach (var method in calls)
                try
                {
                    SimpleDeobfuscator.DeobfuscateBlocks(method);
                    if (method.MethodSig.RetType.FullName != "System.Int32" ||
                        method.Body.Instructions.Count != 4)
                        continue;

                    if (!method.Body.Instructions[0].IsLdarg() ||
                        !method.Body.Instructions[1].OpCode.Equals(OpCodes.Ldfld) ||
                        (!method.Body.Instructions[2].OpCode.Equals(OpCodes.Callvirt) &&
                         !method.Body.Instructions[2].OpCode.Equals(OpCodes.Call)) ||
                        !method.Body.Instructions[3].OpCode.Equals(OpCodes.Ret))
                        continue;

                    if (!method.Body.Instructions[2].Operand.ToString()!.Contains("System.Int32"))
                        continue;

                    for (var i = 0; i < decrypterMethod.Body.Instructions.Count; i++)
                        try
                        {
                            var skip = CheckNet6Calls(decrypterMethod, i, method);
                            if (skip)
                            {
                                popCallsCount = 4;
                                break;
                            }

                            if (!decrypterMethod.Body.Instructions[i].IsLdloc() ||
                                !decrypterMethod.Body.Instructions[i + 1].OpCode.Equals(OpCodes.Callvirt) ||
                                decrypterMethod.Body.Instructions[i + 1].Operand is not MethodDef calledMethod ||
                                !decrypterMethod.Body.Instructions[i + 2].OpCode.Equals(OpCodes.Pop))
                                continue;

                            if (MethodEqualityComparer.CompareDeclaringTypes.Equals(calledMethod, method))
                                popCallsCount++;
                        }
                        catch { }
                    
                    return true;
                }
                catch { }

            return false;
        }

        private bool CheckNet6Calls(MethodDef decrypterMethod, int i, MethodDef method)
        {
            //.NET 6+ doesn't only pop 4 times, it assigns them and does some obfuscated things,
            //but they don't seem to be important
            var inst = decrypterMethod.Body.Instructions;
            if (!inst[i].IsLdloc() ||
                !inst[i + 1].OpCode.Equals(OpCodes.Callvirt) ||
                inst[i + 1].Operand is not MethodDef calledMethod1 ||
                !inst[i + 2].IsStloc() ||
                
                !inst[i + 3].IsLdloc() ||
                !inst[i + 4].OpCode.Equals(OpCodes.Callvirt) ||
                inst[i + 4].Operand is not MethodDef calledMethod2 ||
                !inst[i + 5].OpCode.Equals(OpCodes.Stsfld) ||
                
                !inst[i + 6].IsLdloc() ||
                !inst[i + 7].OpCode.Equals(OpCodes.Callvirt) ||
                inst[i + 7].Operand is not MethodDef calledMethod3 ||
                !inst[i + 8].OpCode.Equals(OpCodes.Pop) ||
                
                !inst[i + 9].IsLdloc() ||
                !inst[i + 10].OpCode.Equals(OpCodes.Callvirt) ||
                inst[i + 10].Operand is not MethodDef calledMethod4 ||
                !inst[i + 11].IsStloc())
                return false;

            return MethodEqualityComparer.CompareDeclaringTypes.Equals(calledMethod1, method) &&
                   MethodEqualityComparer.CompareDeclaringTypes.Equals(calledMethod2, method) &&
                   MethodEqualityComparer.CompareDeclaringTypes.Equals(calledMethod3, method) &&
                   MethodEqualityComparer.CompareDeclaringTypes.Equals(calledMethod4, method);
        }

        private bool RestoreMethodsBody(byte[] bytes)
        {
            var dumpedMethods = new DumpedMethods();
            XorEncrypt(bytes, GetXorKey(_encryptedResource.DecrypterMethod));
            var isFindDnrMethod = FindDnrCompileMethod(_encryptedResource.DecrypterMethod) != null;
            var methodsDataReader = ByteArrayDataReaderFactory.CreateReader(bytes);

            int tmp;
            if (FindBinaryReaderMethod(out var popCallsCount) && popCallsCount > 3)
                for (var i = 0; i < popCallsCount; i++)
                    methodsDataReader.ReadInt32();
            else
            {
                tmp = methodsDataReader.ReadInt32();
                if ((tmp & -16777216L) == 100663296L)
                    methodsDataReader.ReadInt32();
                else
                    methodsDataReader.Position -= 4U;
            }

            var patchCount = methodsDataReader.ReadInt32();
            if (patchCount > methodsDataReader.BytesLeft / 8)
                patchCount = methodsDataReader.ReadInt32();

            var mode = methodsDataReader.ReadInt32();
            tmp = methodsDataReader.ReadInt32();
            methodsDataReader.Position -= 4U;
            if ((tmp & -16777216L) == 100663296L)
            {
                methodsDataReader.Position += (uint)(8 * patchCount);
                patchCount = methodsDataReader.ReadInt32();
                mode = methodsDataReader.ReadInt32();
                PatchDwords(Context.PeImage, ref methodsDataReader, patchCount);
                while (methodsDataReader.Position < (ulong)(bytes.Length - 1))
                {
                    methodsDataReader.ReadUInt32();
                    var numDwords = methodsDataReader.ReadInt32();
                    PatchDwords(Context.PeImage, ref methodsDataReader, numDwords / 2);
                }
            }
            else
            {
                if (!isFindDnrMethod || mode == 1)
                {
                    PatchDwords(Context.PeImage, ref methodsDataReader, patchCount);
                    var isNewer45Decryption = IsNewer45Decryption(_encryptedResource.DecrypterMethod);
                    var isUsingOffset = !IsUsingRva(_encryptedResource.DecrypterMethod);
                    while (methodsDataReader.Position < (ulong)(bytes.Length - 1))
                    {
                        var rva = (uint)methodsDataReader.ReadInt32();
                        int size;
                        if (!isNewer45Decryption)
                        {
                            methodsDataReader.ReadInt32();
                            size = methodsDataReader.ReadInt32();
                        }
                        else
                            size = methodsDataReader.ReadInt32() * 4;

                        var newData = methodsDataReader.ReadBytes(size);
                        if (Context.Info.NativeStub && isUsingOffset)
                            Context.PeImage.DotNetSafeWriteOffset(rva, newData);
                        else
                            Context.PeImage.DotNetSafeWrite(rva, newData);
                    }
                }
                else
                {
                    var methodDef = Context.PeImage.Metadata.TablesStream.MethodTable;
                    var rvaToIndex = new Dictionary<uint, int>((int)methodDef.Rows);
                    var offset = (uint)methodDef.StartOffset;
                    var i = 0;
                    while (i < methodDef.Rows)
                    {
                        var rva2 = Context.PeImage.OffsetReadUInt32(offset);
                        offset += methodDef.RowSize;
                        if (rva2 != 0U)
                        {
                            if ((Context.PeImage.ReadByte(rva2) & 3) == 2)
                                rva2 += 1U;
                            else
                                rva2 += (uint)(4 * (Context.PeImage.ReadByte(rva2 + 1U) >> 4));
                            rvaToIndex[rva2] = i;
                        }

                        i++;
                    }

                    PatchDwords(Context.PeImage, ref methodsDataReader, patchCount);
                    methodsDataReader.ReadInt32();
                    while (methodsDataReader.Position < (ulong)(bytes.Length - 1))
                    {
                        var rva3 = methodsDataReader.ReadUInt32();
                        var index = methodsDataReader.ReadUInt32();
                        var isNativeCode = index >= 1879048192U;
                        var size2 = methodsDataReader.ReadInt32();
                        var methodData = methodsDataReader.ReadBytes(size2);
                        if (!rvaToIndex.TryGetValue(rva3, out var methodIndex))
                            continue;
                        var methodToken = (uint)(100663297 + methodIndex);
                        if (isNativeCode)
                        {
                            if (DeobUtils.IsCode(_nativeLdci4, methodData))
                            {
                                var int32 = BitConverter.ToUInt32(methodData, 4);
                                methodData = new byte[]
                                {
                                    32, (byte)int32, (byte)(int32 >> 8), (byte)(int32 >> 16), (byte)(int32 >> 24), 42
                                };
                            }
                            else
                                methodData = DeobUtils.IsCode(_nativeLdci40, methodData)
                                    ? new byte[] { 22, 42 }
                                    : new byte[] { 32, 222, 192, 173, 222, 109, 122 };
                        }

                        var dumpedMethod = new DumpedMethod();
                        Context.PeImage.ReadMethodTableRowTo(dumpedMethod,
                            MDToken.ToRID(methodToken));
                        dumpedMethod.code = methodData;
                        var codeReader = Context.PeImage.Reader;
                        codeReader.Position = Context.PeImage.RvaToOffset(dumpedMethod.mdRVA);
                        var mbHeader = MethodBodyParser.ParseMethodBody(ref codeReader, out _,
                            out dumpedMethod.extraSections);
                        Context.PeImage.UpdateMethodHeaderInfo(dumpedMethod, mbHeader);
                        dumpedMethods.Add(dumpedMethod);
                    }
                }
            }

            using (Context.Module)
            {
                if (!isFindDnrMethod || mode == 1)
                    Context.Module = Context.AssemblyModule.Reload(
                        Context.PeImage.PeImageData, CreateDumpedMethodsRestorer(dumpedMethods), null);
                else if (dumpedMethods.Count > 0)
                    Context.Module = Context.AssemblyModule.Reload(
                        Context.ModuleBytes, CreateDumpedMethodsRestorer(dumpedMethods), null);
                else
                    return false;
            }

            return true;
        }

        private static bool IsNewer45Decryption(MethodDef method)
        {
            if (method?.Body == null)
                return false;
            for (var i = 0; i < method.Body.Instructions.Count - 4; i++)
                if (method.Body.Instructions[i].IsLdcI4())
                    if (method.Body.Instructions[i + 1].OpCode.Code.Equals(Code.Mul))
                        if (method.Body.Instructions[i + 2].IsLdcI4())
                            if (method.Body.Instructions[i + 3].OpCode.Code.Equals(Code.Ldloca_S) ||
                                method.Body.Instructions[i + 3].OpCode.Code.Equals(Code.Ldloca))
                                if (method.Body.Instructions[i + 4].OpCode.Code.Equals(Code.Call))
                                    return true;
            return false;
        }

        private static bool IsUsingRva(MethodDef method)
        {
            if (method?.Body == null)
                return false;
            var instrs = method.Body.Instructions;
            return instrs.Where((t, i) => t.OpCode.Equals(OpCodes.Ldloca_S) &&
                                          instrs[i + 1].OpCode.Equals(OpCodes.Ldsfld) &&
                                          instrs[i + 2].OpCode.Equals(OpCodes.Ldloc_S) &&
                                          instrs[i + 3].OpCode.Equals(OpCodes.Conv_I8) &&
                                          instrs[i + 4].OpCode.Equals(OpCodes.Add) &&
                                          instrs[i + 5].OpCode.Equals(OpCodes.Ldloc_S) &&
                                          instrs[i + 6].OpCode.Equals(OpCodes.Conv_I8) &&
                                          instrs[i + 7].OpCode.Equals(OpCodes.Sub) &&
                                          instrs[i + 8].OpCode.Code.Equals(Code.Call)).Any();
        }

        private static CompileMethodType GetCompileMethodType(IMethod method, string paramStruct = null)
        {
            if (DotNetUtils.IsMethod(method, "System.UInt32",
                    "(System.UInt64&,System.IntPtr,System.IntPtr,System.UInt32,System.IntPtr&,System.UInt32&)"))
                return CompileMethodType.V1;
            
            if (DotNetUtils.IsMethod(method, "System.UInt32",
                    "(System.IntPtr,System.IntPtr,System.IntPtr,System.UInt32,System.IntPtr,System.UInt32&)"))
                return CompileMethodType.V2;
            
            return paramStruct != null && DotNetUtils.IsMethod(method, "System.UInt32",
                $"(System.IntPtr,System.IntPtr,{paramStruct}&,System.UInt32,System.IntPtr,System.UInt32&)")
                ? CompileMethodType.V3
                : CompileMethodType.Unknown;
        }

        private static DumpedMethodsRestorer CreateDumpedMethodsRestorer(DumpedMethods dumpedMethods)
        {
            if (dumpedMethods == null || dumpedMethods.Count == 0)
                return null;
            return new DumpedMethodsRestorer(dumpedMethods);
        }

        private static long GetXorKey(MethodDef method)
        {
            for (var i = 0; i < method.Body.Instructions.Count - 1; i++)
            {
                if (method.Body.Instructions[i].OpCode.Code.Equals(Code.Ldind_I8))
                {
                    var ldci4 = method.Body.Instructions[i + 1];
                    long result;
                    if (ldci4.IsLdcI4())
                        result = ldci4.GetLdcI4Value();
                    else
                    {
                        if (!ldci4.OpCode.Code.Equals(Code.Ldc_I8))
                            goto Continue;
                        result = (long)ldci4.Operand;
                    }

                    return result;
                }

                Continue: ;
            }

            return 0;
        }

        private static MethodDef FindDnrCompileMethod(MethodDef methodDef)
        {
            var type = methodDef.DeclaringType;
            var methodCandidates = (from method in type.Methods
                where method.IsStatic && method.Body != null
                let sig = method.MethodSig
                where sig != null && sig.Params.Count == 6
                select method).ToList();
            var dnrCompileMethod = methodCandidates.FirstOrDefault(method => GetCompileMethodType(method) != CompileMethodType.Unknown);

            if (dnrCompileMethod == null)
            {
                //.NET 6+ has a different compile method signature
                var paramStruct = type.NestedTypes.FirstOrDefault(typeDef => 
                    typeDef.Fields.Count == 4 && 
                    typeDef.Fields[0].FieldType.FullName == "System.IntPtr" && 
                    typeDef.Fields[1].FieldType.FullName == "System.IntPtr" && 
                    typeDef.Fields[2].FieldType.FullName == "System.IntPtr" && 
                    typeDef.Fields[3].FieldType.FullName == "System.Int32");

                if (paramStruct != null)
                {
                    var operands = methodDef.Body.Instructions
                        .Where(x => x.OpCode.Equals(OpCodes.Ldftn) && x.Operand is MethodDef)
                        .Select(x => x.Operand);
                    dnrCompileMethod = methodCandidates.Where(method =>
                        GetCompileMethodType(method, paramStruct.FullName) != CompileMethodType.Unknown)
                        .FirstOrDefault(x => operands.Contains(x));
                }
            }

            return dnrCompileMethod;
        }

        private static void PatchDwords(MyPeImage peImage, ref DataReader reader, int count)
        {
            for (var i = 0; i < count; i++)
            {
                var rva = reader.ReadUInt32();
                var data = reader.ReadUInt32();
                peImage.DotNetSafeWrite(rva, BitConverter.GetBytes(data));
            }
        }

        private static void XorEncrypt(byte[] data, long xorKey)
        {
            if (xorKey == 0L)
                return;
            var stream = new MemoryStream(data);
            var reader = new BinaryReader(stream);
            var writer = new BinaryWriter(stream);
            var count = data.Length / 8;
            for (var i = 0; i < count; i++)
            {
                var val = reader.ReadInt64();
                val ^= xorKey;
                stream.Position -= 8L;
                writer.Write(val);
            }
        }


        private IContext Context { get; set; }
        private readonly short[] _nativeLdci4 = { 85, 139, 236, 184, -1, -1, -1, -1, 93, 195 };
        private readonly short[] _nativeLdci40 = { 85, 139, 236, 51, 192, 93, 195 };
        private EncryptedResource _encryptedResource;

        private enum CompileMethodType { Unknown, V1, V2, V3 }
    }
}