$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class LicensingProbe {
 [DllImport("ole32.dll",ExactSpelling=true)]
 public static extern int CoCreateInstance(ref Guid clsid,IntPtr outer,uint context,ref Guid iid,out IntPtr manager);
 [DllImport("slc.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
 public static extern int SLGetWindowsInformation(string value, out uint type, out uint length, out IntPtr data);
 [DllImport("kernel32.dll",ExactSpelling=true)] public static extern IntPtr LocalFree(IntPtr data);
 public static string Probe() {
   IntPtr manager=IntPtr.Zero,os=IntPtr.Zero;
   try {
     Guid clsid=new Guid("22f5b1df-7d7a-4d21-97f8-c21aefba859c"),app=new Guid("90e2000c-b946-42fa-892f-94506f30ca4f");
     int hr=CoCreateInstance(ref clsid,IntPtr.Zero,4,ref app,out manager);
     if(hr<0)return "Create=0x"+hr.ToString("X8");
     Guid iid=new Guid("9bb0f3fe-bcf3-4287-96b4-74fc6da8d7c3");
     hr=Marshal.QueryInterface(manager,ref iid,out os);
     return "Create=OK; IOperatingSystemLicenseManager2=0x"+hr.ToString("X8");
   }finally{if(os!=IntPtr.Zero)Marshal.Release(os);if(manager!=IntPtr.Zero)Marshal.Release(manager);}
 }
 public static string Info(string name){
   IntPtr data=IntPtr.Zero;uint type,len;
   int hr=SLGetWindowsInformation(name,out type,out len,out data);
   try{return hr<0?name+"=0x"+hr.ToString("X8"):name+" type="+type+" length="+len+" value="+(type==1?Marshal.PtrToStringUni(data):len==4?Marshal.ReadInt32(data).ToString():"binary");}
   finally{if(data!=IntPtr.Zero)LocalFree(data);}
 }
}
'@
[LicensingProbe]::Probe()
[LicensingProbe]::Info('Clip-SubscriptionPFN')
[LicensingProbe]::Info('Clip-SubscriptionEditionId')
