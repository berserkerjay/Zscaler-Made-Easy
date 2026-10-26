' Exists only for shortcuts made before the rename to Zscaler Made Easy; START_Zscaler_Made_Easy.vbs is the launcher.
' Runs it with the same arguments (such as /restart), waits, and returns its exit code.
Option Explicit
Dim sh, fso, launcher, args, i, rc
On Error Resume Next
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
launcher = fso.BuildPath(fso.GetParentFolderName(WScript.ScriptFullName), "START_Zscaler_Made_Easy.vbs")
args = ""
For i = 0 To WScript.Arguments.Count - 1
  args = args & " """ & WScript.Arguments(i) & """"
Next
rc = sh.Run("wscript.exe //B //Nologo """ & launcher & """" & args, 0, True)
If Err.Number <> 0 Then rc = 1
WScript.Quit rc
