# Dot-source only; compile native bindings on first verification (Windows PowerShell 5.1).
# Offline trust is relative to this machine's existing trust stores/cache. No revocation
# checking, downloads, installation, catalog registration, or execution is performed.
# Valid is signature validity, NOT a publisher allowlist or permission to execute.
# The file lock lasts through verification/name extraction, not through a later launch.
# Microsoft references:
# https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-winverifytrust
# https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_data
# https://learn.microsoft.com/windows/win32/api/wintrust/ns-wintrust-wintrust_catalog_info
# https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-wthelpergetprovsignerfromchain
# https://learn.microsoft.com/windows/win32/api/mscat/nf-mscat-cryptcatadmincalchashfromfilehandle2
# https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Security/CodeSigning/cpp/codesigning.cpp
function Initialize-WBOfflineSignatureNative {
    if ('USBWinBatch.OfflineSignature' -as [type]) { return }
    Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace USBWinBatch {
    public sealed class OfflineSignatureResult {
        public string Status { get; internal set; }
        public string SignerName { get; internal set; }
        public string SignatureKind { get; internal set; }
        public string SignerSubject { get; internal set; }
        public string SignerThumbprint { get; internal set; }
        public int NativeError { get; internal set; }
    }

    public static class OfflineSignature {
        const uint WTD_UI_NONE = 2, WTD_REVOKE_NONE = 0;
        const uint WTD_CHOICE_FILE = 1, WTD_CHOICE_CATALOG = 2;
        const uint WTD_STATEACTION_VERIFY = 1, WTD_STATEACTION_CLOSE = 2;
        const uint WTD_REVOCATION_CHECK_NONE = 0x10;
        const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000, WTD_DISABLE_MD2_MD4 = 0x2000;
        const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
        const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
        static readonly Guid VerifyAction = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        static readonly Guid CatalogSubsystem = new Guid("F750E6C3-38EE-11d1-85E5-00C04FC295EE");

        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
        struct TrustFile {
            public uint Size;
            [MarshalAs(UnmanagedType.LPWStr)] public string Path;
            public IntPtr File, Subject;
        }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
        struct TrustCatalog {
            public uint Size, Version;
            [MarshalAs(UnmanagedType.LPWStr)] public string CatalogPath;
            [MarshalAs(UnmanagedType.LPWStr)] public string MemberTag;
            [MarshalAs(UnmanagedType.LPWStr)] public string MemberPath;
            public IntPtr MemberFile, Hash;
            public uint HashSize;
            public IntPtr CatalogContext, Admin;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct TrustData {
            public uint Size;
            public IntPtr Policy, Sip;
            public uint UI, Revocation, Choice;
            public IntPtr Info;
            public uint StateAction;
            public IntPtr State, Url;
            public uint Flags, UIContext;
            public IntPtr SignatureSettings;
        }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
        struct CatalogInfo {
            public uint Size;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)] public string Path;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct ProviderSigner {
            public uint Size, TimeLow, TimeHigh, CertCount;
            public IntPtr CertChain;
            public uint SignerType;
            public IntPtr Signer;
            public uint Error, CounterCount;
            public IntPtr Counters, ChainContext;
        }
        // Only the documented prefix is read; default packing preserves pointer alignment.
        [StructLayout(LayoutKind.Sequential)]
        struct ProviderCertPrefix { public uint Size; public IntPtr Cert; }

        // System32 search avoids loading a lookalike DLL from the current directory.
        [DllImport("wintrust.dll", ExactSpelling=true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);
        [DllImport("wintrust.dll", ExactSpelling=true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        static extern IntPtr WTHelperProvDataFromStateData(IntPtr state);
        [DllImport("wintrust.dll", ExactSpelling=true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provider, uint index, [MarshalAs(UnmanagedType.Bool)] bool counter, uint counterIndex);
        [DllImport("wintrust.dll", ExactSpelling=true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        static extern IntPtr WTHelperGetProvCertFromChain(IntPtr signer, uint index);
        [DllImport("wintrust.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CryptCATAdminAcquireContext2(out IntPtr admin, ref Guid subsystem, string algorithm, IntPtr policy, uint flags);
        [DllImport("wintrust.dll", ExactSpelling=true, SetLastError=true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin, IntPtr file, ref uint size, [Out] byte[] hash, uint flags);
        [DllImport("wintrust.dll", ExactSpelling=true, SetLastError=true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte[] hash, uint size, uint flags, ref IntPtr previous);
        [DllImport("wintrust.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CryptCATCatalogInfoFromContext(IntPtr catalog, ref CatalogInfo info, uint flags);
        [DllImport("wintrust.dll", ExactSpelling=true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr catalog, uint flags);
        [DllImport("wintrust.dll", ExactSpelling=true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CryptCATAdminReleaseContext(IntPtr admin, uint flags);
        [DllImport("kernel32.dll", ExactSpelling=true, CharSet=CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        static extern uint GetDriveTypeW(string root);
        [DllImport("kernel32.dll", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, uint size, uint flags);

        static OfflineSignatureResult Fail(string status, int error) {
            return new OfflineSignatureResult { Status=status, SignerName="", SignatureKind="",
                SignerSubject="", SignerThumbprint="", NativeError=error };
        }
        static string LocalPath(string path, string extension) {
            // Deliberately accept only canonical, local drive-absolute paths. Reject UNC,
            // device paths, ADS, arguments, wildcards, DOS devices and ambiguous components.
            if (String.IsNullOrWhiteSpace(path) || path.Length >= 260 || path.Length < 4 ||
                !((path[0]>='A' && path[0]<='Z') || (path[0]>='a' && path[0]<='z')) ||
                path[1]!=':' || path[2]!='\\' || path.IndexOf('/', 0)>=0 ||
                path.IndexOf(':', 2)>=0 || path.IndexOfAny(Path.GetInvalidPathChars())>=0 ||
                !String.Equals(Path.GetExtension(path), extension, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Expected a local absolute executable path.");
            string[] parts=path.Substring(3).Split('\\');
            foreach(string part in parts) {
                if (part.Length==0 || part=="." || part==".." || part.EndsWith(".") || part.EndsWith(" ") ||
                    part.IndexOfAny(Path.GetInvalidFileNameChars())>=0)
                    throw new ArgumentException("Ambiguous path component.");
                string stem=part.Split('.')[0].ToUpperInvariant();
                if(stem=="CON" || stem=="PRN" || stem=="AUX" || stem=="NUL" ||
                    (stem.Length==4 && (stem.StartsWith("COM") || stem.StartsWith("LPT")) &&
                     "123456789\u00b9\u00b2\u00b3".IndexOf(stem[3])>=0))
                    throw new ArgumentException("Device path.");
            }
            uint drive=GetDriveTypeW(path.Substring(0,3));
            if(drive!=2 && drive!=3 && drive!=6) throw new ArgumentException("Nonlocal drive.");
            string current=path.Substring(0,3);
            foreach(string part in parts) {
                current=Path.Combine(current,part);
                FileAttributes attributes=File.GetAttributes(current);
                if((attributes & (FileAttributes.ReparsePoint | FileAttributes.Offline))!=0)
                    throw new ArgumentException("Reparse or offline path.");
            }
            return Path.GetFullPath(path);
        }
        static FileStream OpenReadLocked(string path) {
            FileStream stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
            try {
                StringBuilder resolved=new StringBuilder(32768);
                uint n=GetFinalPathNameByHandleW(stream.SafeFileHandle,resolved,(uint)resolved.Capacity,0);
                if(n==0 || n>=resolved.Capacity) throw new IOException("Cannot resolve file handle.");
                // Final handle identity check also rejects filesystem redirection/aliases.
                if(!String.Equals(resolved.ToString(),@"\\?\"+path,StringComparison.OrdinalIgnoreCase))
                    throw new ArgumentException("Resolved file differs from requested path.");
                return stream;
            } catch { stream.Dispose(); throw; }
        }
        static bool IsExecutable(FileStream stream) {
            if(stream.Length<64) return false;
            BinaryReader reader=new BinaryReader(stream,Encoding.UTF8,true);
            try {
                stream.Position=0;
                if(reader.ReadUInt16()!=0x5A4D) return false;
                stream.Position=60;
                uint offset=reader.ReadUInt32();
                if(offset<64 || (long)offset+26>stream.Length) return false;
                stream.Position=offset;
                if(reader.ReadUInt32()!=0x00004550) return false;
                stream.Position=offset+20;
                ushort optionalSize=reader.ReadUInt16(), characteristics=reader.ReadUInt16();
                ushort magic=reader.ReadUInt16();
                return (characteristics & 2)!=0 && (characteristics & 0x2000)==0 &&
                    (magic==0x10B || magic==0x20B) && optionalSize>=(magic==0x20B?112:96) &&
                    (long)offset+24+optionalSize<=stream.Length;
            } finally { reader.Dispose(); stream.Position=0; }
        }
        static OfflineSignatureResult VerifyObject(object info, uint choice, string kind) {
            IntPtr buffer=Marshal.AllocHGlobal(Marshal.SizeOf(info));
            bool initialized=false;
            TrustData data=new TrustData();
            Guid action=VerifyAction;
            try {
                Marshal.StructureToPtr(info,buffer,false); initialized=true;
                data.Size=(uint)Marshal.SizeOf(typeof(TrustData));
                data.UI=WTD_UI_NONE; data.Revocation=WTD_REVOKE_NONE;
                data.Choice=choice; data.Info=buffer; data.StateAction=WTD_STATEACTION_VERIFY;
                data.Flags=WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4;
                int error=WinVerifyTrust(new IntPtr(-1),ref action,ref data);
                if(error!=0) return Fail(error==TRUST_E_NOSIGNATURE?"NotSigned":error==TRUST_E_BAD_DIGEST?"HashMismatch":"Untrusted",error);
                // Never extract from a separately parsed file/catalog. This provider state
                // verified this exact member/digest, and index zero is its primary signer,
                // NOT the timestamp countersigner. No alternate signature selection occurs.
                IntPtr provider=WTHelperProvDataFromStateData(data.State);
                if(provider==IntPtr.Zero) return Fail("SignerUnavailable",0);
                IntPtr signer=WTHelperGetProvSignerFromChain(provider,0,false,0);
                if(signer==IntPtr.Zero) return Fail("SignerUnavailable",0);
                ProviderSigner s=(ProviderSigner)Marshal.PtrToStructure(signer,typeof(ProviderSigner));
                if(s.Error!=0 || s.CertCount==0) return Fail("SignerUnavailable",unchecked((int)s.Error));
                IntPtr cert=WTHelperGetProvCertFromChain(signer,0);
                if(cert==IntPtr.Zero) return Fail("SignerUnavailable",0);
                ProviderCertPrefix c=(ProviderCertPrefix)Marshal.PtrToStructure(cert,typeof(ProviderCertPrefix));
                if(c.Size<Marshal.SizeOf(typeof(ProviderCertPrefix)) || c.Cert==IntPtr.Zero) return Fail("SignerUnavailable",0);
                using(X509Certificate2 certificate=new X509Certificate2(c.Cert)) {
                    string name=certificate.GetNameInfo(X509NameType.SimpleName,false);
                    if(String.IsNullOrWhiteSpace(name)) return Fail("SignerUnavailable",0);
                    return new OfflineSignatureResult { Status="Valid", SignerName=name, SignatureKind=kind,
                        SignerSubject=certificate.Subject, SignerThumbprint=certificate.Thumbprint, NativeError=0 };
                }
            } finally {
                // CLOSE on both successful and failed VERIFY, before releasing input memory
                // or either locked file. Provider-owned certificates must not escape this scope.
                try {
                    if(initialized) {
                        data.StateAction=WTD_STATEACTION_CLOSE;
                        WinVerifyTrust(new IntPtr(-1),ref action,ref data);
                    }
                } finally {
                    if(initialized) Marshal.DestroyStructure(buffer,info.GetType());
                    Marshal.FreeHGlobal(buffer);
                }
            }
        }
        static OfflineSignatureResult VerifyCatalogs(string path, FileStream stream) {
            OfflineSignatureResult last=Fail("NotSigned",TRUST_E_NOSIGNATURE);
            // Search the existing local catalog database. SHA256 first, then legacy SHA1;
            // Windows Authenticode policy must still approve the member and catalog signer.
            foreach(string algorithm in new string[] { "SHA256", "SHA1" }) {
                IntPtr admin=IntPtr.Zero, catalog=IntPtr.Zero;
                Guid subsystem=CatalogSubsystem;
                try {
                    if(!CryptCATAdminAcquireContext2(out admin,ref subsystem,algorithm,IntPtr.Zero,0))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    uint size=0;
                    stream.Position=0;
                    if(!CryptCATAdminCalcHashFromFileHandle2(admin,stream.SafeFileHandle.DangerousGetHandle(),ref size,null,0) || size==0 || size>128)
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    byte[] hash=new byte[size];
                    stream.Position=0;
                    if(!CryptCATAdminCalcHashFromFileHandle2(admin,stream.SafeFileHandle.DangerousGetHandle(),ref size,hash,0))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    string tag=BitConverter.ToString(hash,0,(int)size).Replace("-","");
                    // Same enumeration ownership pattern as Microsoft's CodeSigning sample:
                    // each next call consumes the previous context; release the remaining one.
                    catalog=CryptCATAdminEnumCatalogFromHash(admin,hash,size,0,ref catalog);
                    for(int count=0;catalog!=IntPtr.Zero && count<128;count++) {
                        CatalogInfo ci=new CatalogInfo(); ci.Size=(uint)Marshal.SizeOf(typeof(CatalogInfo));
                        if(!CryptCATCatalogInfoFromContext(catalog,ref ci,0)) throw new Win32Exception(Marshal.GetLastWin32Error());
                        string catPath=LocalPath(ci.Path,".cat");
                        using(FileStream catLock=OpenReadLocked(catPath)) {
                            GCHandle pinned=GCHandle.Alloc(hash,GCHandleType.Pinned);
                            try {
                                TrustCatalog input=new TrustCatalog(); input.Size=(uint)Marshal.SizeOf(typeof(TrustCatalog));
                                input.CatalogPath=catPath; input.MemberTag=tag; input.MemberPath=path;
                                input.MemberFile=stream.SafeFileHandle.DangerousGetHandle();
                                input.Hash=pinned.AddrOfPinnedObject(); input.HashSize=size; input.Admin=admin;
                                stream.Position=0;
                                last=VerifyObject(input,WTD_CHOICE_CATALOG,"Catalog");
                                if(last.Status=="Valid") return last;
                            } finally { pinned.Free(); }
                        }
                        catalog=CryptCATAdminEnumCatalogFromHash(admin,hash,size,0,ref catalog);
                    }
                } finally {
                    if(catalog!=IntPtr.Zero) CryptCATAdminReleaseCatalogContext(admin,catalog,0);
                    if(admin!=IntPtr.Zero) CryptCATAdminReleaseContext(admin,0);
                }
            }
            return last;
        }
        public static OfflineSignatureResult Verify(string path) {
            try {
                path=LocalPath(path,".exe");
                using(FileStream stream=OpenReadLocked(path)) {
                    if(!IsExecutable(stream)) return Fail("NotExecutable",0);
                    TrustFile file=new TrustFile(); file.Size=(uint)Marshal.SizeOf(typeof(TrustFile));
                    file.Path=path; file.File=stream.SafeFileHandle.DangerousGetHandle();
                    OfflineSignatureResult result=VerifyObject(file,WTD_CHOICE_FILE,"Embedded");
                    // Never hide a damaged/untrusted embedded signature with another source.
                    // Catalog lookup is only for files with no embedded signature.
                    if(result.Status!="NotSigned") return result;
                    return VerifyCatalogs(path,stream);
                }
            } catch(ArgumentException) { return Fail("InvalidPath",0); }
              catch(IOException ex) { return Fail("FileUnavailable",ex.HResult); }
              catch(UnauthorizedAccessException ex) { return Fail("FileUnavailable",ex.HResult); }
              catch(Win32Exception ex) { return Fail("VerificationError",ex.NativeErrorCode); }
              catch(Exception ex) { return Fail("VerificationError",ex.HResult); }
        }
    }
}
'@
}

function Get-WBOfflineSignature {
    [CmdletBinding()]
    param([Parameter(Position=0)][AllowNull()][AllowEmptyString()][string]$Path)
    try {
        Initialize-WBOfflineSignatureNative
        [USBWinBatch.OfflineSignature]::Verify($Path)
    } catch {
        [pscustomobject]@{Status='VerificationError';SignerName='';SignatureKind='';SignerSubject='';SignerThumbprint='';NativeError=$_.Exception.HResult}
    }
}
