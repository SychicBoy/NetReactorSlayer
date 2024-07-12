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
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using NETReactorSlayer.Core.Abstractions;
using NETReactorSlayer.Core.Helper;

namespace NETReactorSlayer.Core.Stages
{
    internal class Cleaner : IStage
    {
        public void Run(IContext context)
        {
            Context = context;
            FindAndRemoveEmptyMethods();
            FixMdHeaderVersion();
            FixEntrypoint();
            RemoveCallsToObfuscatorTypes();
            RemoveJunks();
            RemoveObfuscatorTypes();
        }

        public static void AddCallToBeRemoved(MethodDef method)
        {
            if (method == null || CallsToRemove.Any(x => x.MDToken.ToInt32() == method.MDToken.ToInt32()))
                return;
            MethodsToRemove.Add(method);
            CallsToRemove.Add(method);
        }

        public static void AddMethodToBeRemoved(MethodDef method)
        {
            if (method == null || MethodsToRemove.Any(x => x.MDToken.ToInt32() == method.MDToken.ToInt32()))
                return;
            MethodsToRemove.Add(method);
        }

        public static void AddResourceToBeRemoved(Resource resource)
        {
            if (resource == null || ResourcesToRemove.Any(x => x.Name == resource.Name))
                return;
            ResourcesToRemove.Add(resource);
        }

        public static void AddTypeToBeRemoved(ITypeDefOrRef type) => TypesToRemove.Add(type);

        private void RemoveJunks()
        {
            if (!Context.Options.RemoveJunks)
                return;

            foreach (var type in Context.Module.GetTypes().ToList())
            {
                DeleteEmptyConstructors(type);

                foreach (var method in type.Methods.ToList())
                {
                    RemoveAttributes(method);

                    if (!method.HasBody)
                        continue;

                    if (RemoveMethodIfDnrTrial(method))
                        continue;

                    FindAndRemoveDummyTypes(method);

                    if (RemoveMethodIfDummy(method))
                        continue;

                    SimpleDeobfuscator.Deobfuscate(method);
                }

                foreach (var field in type.Fields)
                    RemoveAttributes(field);
            }
        }

        private void RemoveObfuscatorTypes()
        {
            if (Context.Options.KeepObfuscatorTypes)
                return;
            foreach (var method in MethodsToRemove)
                try
                {
                    method.DeclaringType.Remove(method);
                }
                catch { }

            foreach (var typeDef in TypesToRemove.Select(type => type.ResolveTypeDef()))
                try
                {
                    if (typeDef.DeclaringType != null)
                        typeDef.DeclaringType.NestedTypes.Remove(typeDef);
                    else
                        Context.Module.Types.Remove(typeDef);
                }
                catch { }

            foreach (var rsrc in ResourcesToRemove)
                try { Context.Module.Resources.Remove(Context.Module.Resources.Find(rsrc.Name)); } catch { }
        }

        private void FixEntrypoint()
        {
            try
            {
                if (!Context.Module.IsEntryPointValid ||
                    !Context.Module.EntryPoint.DeclaringType.Name.Contains("<PrivateImplementationDetails>"))
                    return;
                if ((Context.Module.EntryPoint.Body.Instructions
                        .Last(x => x.OpCode == OpCodes.Call && x.Operand is IMethod iMethod &&
                                   iMethod.ResolveMethodDef().IsStatic).Operand as IMethod)
                    .ResolveMethodDef() is not { } entryPoint)
                    return;
                foreach (var attribute in Context.Module.EntryPoint.CustomAttributes)
                    entryPoint.CustomAttributes.Add(attribute);
                if (entryPoint.HasParams() && Context.Module.EntryPoint.HasParams() &&
                    entryPoint.Parameters.First().Type.FullName == "System.Object")
                    entryPoint.Parameters.First().Type = Context.Module.EntryPoint.Parameters.First().Type;
                if (Context.Module.EntryPoint.DeclaringType.DeclaringType != null)
                    Context.Module.EntryPoint.DeclaringType.DeclaringType.NestedTypes.Remove(
                        Context.Module.EntryPoint.DeclaringType);
                else
                    Context.Module.Types.Remove(Context.Module.EntryPoint.DeclaringType);
                Context.Logger.Info(
                    $"Entrypoint fixed: {Context.Module.EntryPoint.MDToken.ToInt32()} -> {entryPoint.MDToken.ToInt32()}");
                Context.Module.EntryPoint = entryPoint;
            }
            catch { }
        }

        private void FixMdHeaderVersion()
        {
            if (Context.Module.TablesHeaderVersion == 0x0101)
                Context.Module.TablesHeaderVersion = 0x0200;
        }

        private void RemoveCallsToObfuscatorTypes()
        {
            if (!Context.Options.RemoveCallsToObfuscatorTypes || CallsToRemove.Count <= 0)
                return;

            try
            {
                var count = MethodCallRemover.RemoveCalls(Context, CallsToRemove.ToList());
                if (count > 0)
                    Context.Logger.Info(
                        $"{count} Calls to obfuscator types removed.");
                else
                    Context.Logger.Warn("Couldn't find any call to the obfuscator types.");
            }
            catch { }
        }

        private void FindAndRemoveDummyTypes(MethodDef method)
        {
            try
            {
                if (_methodCallCounter == null ||
                    (!method.IsConstructor && !method.IsStaticConstructor &&
                     method != Context.Module.EntryPoint))
                    return;
                foreach (var calledMethod in from calledMethod in DotNetUtils.GetCalledMethods(Context.Module, method)
                         where calledMethod.IsStatic && calledMethod.Body != null
                         where DotNetUtils.IsMethod(calledMethod, "System.Void", "()")
                         where IsEmptyMethod(calledMethod)
                         select calledMethod)
                    _methodCallCounter?.Add(calledMethod);

                var numCalls = 0;
                var methodDef = (MethodDef)_methodCallCounter?.Most(out numCalls);
                if (numCalls < 10)
                    return;
                MethodCallRemover.RemoveCalls(Context, methodDef);
                try
                {
                    if (methodDef?.DeclaringType.DeclaringType != null)
                        methodDef.DeclaringType.DeclaringType.NestedTypes.Remove(methodDef.DeclaringType);
                    else
                        Context.Module.Types.Remove(methodDef?.DeclaringType);
                }
                catch { }

                _methodCallCounter = null;
            }
            catch { }
        }

        private static bool RemoveMethodIfDummy(MethodDef method)
        {
            try
            {
                if (method.Body.Instructions.Count == 4 &&
                    method.Body.Instructions[0].OpCode.Equals(OpCodes.Ldsfld) &&
                    method.Body.Instructions[1].OpCode.Equals(OpCodes.Ldnull) &&
                    method.Body.Instructions[2].OpCode.Equals(OpCodes.Ceq) &&
                    method.Body.Instructions[3].OpCode.Equals(OpCodes.Ret))
                    if (method.Body.Instructions[0].Operand is FieldDef { IsPublic: false } field &&
                        (field.FieldType.FullName == "System.Object" || (field.DeclaringType != null &&
                                                                         field.FieldType.FullName ==
                                                                         field.DeclaringType.FullName)))
                        foreach (var method2 in method.DeclaringType.Methods
                                     .Where(x => x.HasBody && x.Body.HasInstructions && x.Body.Instructions.Count == 2)
                                     .ToList().Where(method2 => !method2.IsPublic &&
                                                                (method2.ReturnType.FullName == "System.Object" ||
                                                                 (method2.DeclaringType != null &&
                                                                  method2.ReturnType.FullName ==
                                                                  field.DeclaringType.FullName)))
                                     .Where(method2 => method2.Body.Instructions[0].OpCode.Equals(OpCodes.Ldsfld) &&
                                                       method2.Body.Instructions[1].OpCode.Equals(OpCodes.Ret)))
                        {
                            if (method2.Body.Instructions[0].Operand is not FieldDef field2 ||
                                field2.MDToken.ToInt32() != field.MDToken.ToInt32())
                                continue;
                            try { method.DeclaringType.Remove(method); } catch { }

                            try { method2.DeclaringType.Remove(method2); } catch { }

                            try { field.DeclaringType.Fields.Remove(field); } catch { }

                            return true;
                        }
            }
            catch { }

            return false;
        }

        private void FindAndRemoveEmptyMethods()
        {
            if (!Context.Options.RemoveJunks)
                return;
            foreach (var method in Context.Module.GetTypes().SelectMany(type => type.Methods.Where(x => x.HasBody)))
                try
                {
                    if (method.DeclaringType == null ||
                        !DotNetUtils.IsMethod(method, "System.Void", "()") ||
                        !method.IsStatic ||
                        !method.IsAssembly ||
                        !DotNetUtils.IsEmpty(method) ||
                        method.DeclaringType.Methods.Any(x => DotNetUtils.GetMethodCalls(x).Contains(method)))
                        continue;
                    AddCallToBeRemoved(method);
                }
                catch { }
        }

        private bool RemoveMethodIfDnrTrial(MethodDef method)
        {
            if (!method.Body.HasInstructions || !method.Body.Instructions.Any(x =>
                    x.OpCode.Equals(OpCodes.Ldstr) && x.Operand != null && (x.Operand.ToString() ==
                                                                            "This assembly is protected by an unregistered version of Eziriz's \".NET Reactor\"!" ||
                                                                            x.Operand.ToString() ==
                                                                            "This assembly is protected by an unregistered version of Eziriz's \".NET Reactor\"! This assembly won't further work.")))
                return false;

            if (method.DeclaringType is { BaseType.FullName: "System.Windows.Forms.Form" })
                return false;

            MethodCallRemover.RemoveCalls(Context, method);
            if (method.DeclaringType is { IsGlobalModuleType: false })
                Context.Module.Types.Remove(method.DeclaringType);
            else if (DotNetUtils.IsMethod(method, "System.Void", "()"))
                method.Body = new CilBody { Instructions = { OpCodes.Ret.ToInstruction() } };
            return true;
        }

        private static bool GetMethodImplOptions(CustomAttribute cA, ref int value)
        {
            if (cA.IsRawBlob)
                return false;
            if (cA.ConstructorArguments.Count != 1)
                return false;
            if (cA.ConstructorArguments[0].Type.ElementType != ElementType.I2 &&
                cA.ConstructorArguments[0].Type.FullName != "System.Runtime.CompilerServices.MethodImplOptions")
                return false;
            var arg = cA.ConstructorArguments[0].Value;
            switch (arg)
            {
                case short @int:
                    value = @int;
                    return true;
                case int int1:
                    value = int1;
                    return true;
                default:
                    return false;
            }
        }

        private static void RemoveAttributes(IHasCustomAttribute member)
        {
            try
            {
                if (member is MethodDef method)
                {
                    method.IsNoInlining = false;
                    method.IsSynchronized = false;
                    method.IsNoOptimization = false;
                }

                for (var i = 0; i < member.CustomAttributes.Count; i++)
                    try
                    {
                        var cattr = member.CustomAttributes[i];
                        if (cattr.Constructor.FullName ==
                            "System.Void System.Diagnostics.DebuggerHiddenAttribute::.ctor()")
                        {
                            member.CustomAttributes.RemoveAt(i);
                            i--;
                            continue;
                        }

                        switch (cattr.TypeFullName)
                        {
                            case "System.Diagnostics.DebuggerStepThroughAttribute":
                                member.CustomAttributes.RemoveAt(i);
                                i--;
                                continue;
                            case "System.Diagnostics.DebuggerNonUserCodeAttribute":
                                member.CustomAttributes.RemoveAt(i);
                                i--;
                                continue;
                            case "System.Diagnostics.DebuggerBrowsableAttribute":
                                member.CustomAttributes.RemoveAt(i);
                                i--;
                                continue;
                        }

                        if (cattr.TypeFullName != "System.Runtime.CompilerServices.MethodImplAttribute")
                            continue;
                        var options = 0;
                        if (!GetMethodImplOptions(cattr, ref options))
                            continue;
                        if (options != 0 && options != (int)MethodImplAttributes.NoInlining)
                            continue;
                        member.CustomAttributes.RemoveAt(i);
                        i--;
                    }
                    catch { }
            }
            catch { }
        }

        private static void DeleteEmptyConstructors(TypeDef type)
        {
            var cctor = type.FindStaticConstructor();
            if (cctor == null || !DotNetUtils.IsEmpty(cctor))
                return;
            try { cctor.DeclaringType.Methods.Remove(cctor); } catch { }
        }

        private static bool IsEmptyMethod(MethodDef methodDef)
        {
            if (!DotNetUtils.IsEmptyObfuscated(methodDef))
                return false;

            var type = methodDef.DeclaringType;
            if (type.HasEvents || type.HasProperties)
                return false;
            if (type.Fields.Count != 1 && type.Fields.Count != 2)
                return false;
            switch (type.Fields.Count)
            {
                case 2 when !(type.Fields.Any(x => x.FieldType.FullName == "System.Boolean") &&
                              type.Fields.Any(x => x.FieldType.FullName == "System.Object")):
                    return false;
                case 1 when type.Fields[0].FieldType.FullName != "System.Boolean":
                    return false;
            }

            if (type.IsPublic)
                return false;

            var otherMethods = 0;
            foreach (var method in type.Methods.Where(method => method.Name != ".ctor" && method.Name != ".cctor")
                         .Where(method => method != methodDef))
            {
                otherMethods++;
                if (method.Body == null)
                    return false;
                if (method.Body.Instructions.Count > 20)
                    return false;
            }

            return otherMethods <= 8;
        }


        private IContext Context { get; set; }
        private CallCounter _methodCallCounter = new();
        private static readonly List<MethodDef> CallsToRemove = new();
        private static readonly List<MethodDef> MethodsToRemove = new();
        private static readonly List<Resource> ResourcesToRemove = new();
        private static readonly List<ITypeDefOrRef> TypesToRemove = new();
    }
}