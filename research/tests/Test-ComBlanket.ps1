$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ComBlanketProbe {
 [DllImport("ole32.dll",ExactSpelling=true)] static extern int CoCreateInstance(ref Guid c,IntPtr outer,uint context,ref Guid iid,out IntPtr obj);
 [DllImport("ole32.dll",ExactSpelling=true)] static extern int CoSetProxyBlanket(IntPtr obj,uint authn,uint authz,IntPtr principal,uint level,uint impersonation,IntPtr auth,uint capabilities);
 public static void Run(){
  Guid c=new Guid("22f5b1df-7d7a-4d21-97f8-c21aefba859c"),i=new Guid("9bb0f3fe-bcf3-4287-96b4-74fc6da8d7c3");
  foreach(uint cap in new uint[]{0x800,0,0x40}){
   IntPtr p;int hr=CoCreateInstance(ref c,IntPtr.Zero,4,ref i,out p);
   Console.WriteLine("Create: 0x"+hr.ToString("X8"));
   if(hr<0)continue;
   try{hr=CoSetProxyBlanket(p,0xffffffff,0xffffffff,new IntPtr(-1),0,3,IntPtr.Zero,cap);Console.WriteLine("Blanket cap=0x"+cap.ToString("X")+": 0x"+hr.ToString("X8"));}
   finally{Marshal.Release(p);}
  }
 }
}
'@
[ComBlanketProbe]::Run()
'No licensing call was made.'
