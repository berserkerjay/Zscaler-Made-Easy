' Zscaler Assessment — silent launcher.
' Starts the server with no console window and opens the browser.
' The desktop and Start Menu shortcuts point here. Server output goes to
' server.log next to this file; STOP_Zscaler_Assessment.bat stops it.
Option Explicit
Dim sh, fso, dir, port, logPath, running, sock
Set sh  = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
port = sh.ExpandEnvironmentStrings("%ZSCALER_PORT%")
If port = "%ZSCALER_PORT%" Or port = "" Then port = "8000"
logPath = dir & "\server.log"

' Already running? Then just open the browser.
running = False
On Error Resume Next
Set sock = CreateObject("MSXML2.ServerXMLHTTP.6.0")
sock.setTimeouts 800, 800, 800, 800
sock.open "GET", "http://127.0.0.1:" & port & "/api/write-mode", False
sock.send
If Err.Number = 0 Then running = (sock.status = 200)
Err.Clear
On Error GoTo 0

If Not running Then
  ' Run the normal start script hidden (window style 0), output to server.log.
  ' DLPCHECK_HIDDEN tells the script it is already running silently.
  sh.Environment("PROCESS")("DLPCHECK_HIDDEN") = "1"
  sh.CurrentDirectory = dir
  sh.Run "cmd /c """"" & dir & "\START_Zscaler_Assessment.bat"" > """ & logPath & """ 2>&1""", 0, False
  WScript.Sleep 4000
End If

sh.Run "http://localhost:" & port & "/", 1, False
