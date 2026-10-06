' Zscaler Assessment - silent launcher.
' Starts the server with no console window and opens the browser.
' The desktop and Start Menu shortcuts point here. Server output goes to
' server.log next to this file; STOP_Zscaler_Assessment.bat stops it.
'
' With /restart (used by the Update app button) it first waits for the
' old server to release the port, then starts the new one and does not
' open another browser tab: the page that asked for the update reloads.
'
' Nothing in here may show a Windows Script Host error dialog: every
' step runs under On Error Resume Next and problems are written to
' launcher.log next to this file instead.
Option Explicit
Dim sh, fso, dir, port, logPath, running, restart, waited
Set sh  = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
On Error Resume Next
' The desktop shortcut runs this file directly, so load the same settings
' as the batch launcher before probing the port or opening the browser.
' Re-enter once with the settings inherited from cmd, preserving /restart.
If fso.FileExists(dir & "\local_settings.bat") And sh.Environment("PROCESS")("DLPCHECK_SETTINGS_LOADED") <> "1" Then
  Dim extra, command, result
  extra = ""
  If WScript.Arguments.Count > 0 Then
    If LCase(WScript.Arguments(0)) = "/restart" Then extra = " /restart"
  End If
  sh.Environment("PROCESS")("DLPCHECK_SETTINGS_LOADED") = "1"
  command = "cmd /d /s /c ""call """ & dir & "\local_settings.bat"" && wscript.exe """ & WScript.ScriptFullName & """" & extra & """"
  result = sh.Run(command, 0, True)
  If Err.Number <> 0 Then
    Note "could not load local_settings.bat: " & Err.Description
    WScript.Quit 1
  End If
  WScript.Quit result
End If
' Do not carry the one-time re-entry guard into a later app restart.
sh.Environment("PROCESS")("DLPCHECK_SETTINGS_LOADED") = ""
port = sh.ExpandEnvironmentStrings("%ZSCALER_PORT%")
If port = "%ZSCALER_PORT%" Or port = "" Then port = "8000"
logPath = dir & "\server.log"
restart = False
If WScript.Arguments.Count > 0 Then restart = (LCase(WScript.Arguments(0)) = "/restart")

On Error Resume Next

' Is a server answering on the port?
Function Pinging()
  Dim sock
  Pinging = False
  On Error Resume Next
  Set sock = CreateObject("MSXML2.ServerXMLHTTP.6.0")
  sock.setTimeouts 800, 800, 800, 800
  sock.open "GET", "http://127.0.0.1:" & port & "/api/ping", False
  sock.send
  If Err.Number = 0 Then Pinging = (sock.status = 200)
  Err.Clear
End Function

' One line in launcher.log (never a dialog).
Sub Note(msg)
  Dim f
  On Error Resume Next
  Set f = fso.OpenTextFile(dir & "\launcher.log", 8, True)
  f.WriteLine Now & "  " & msg
  f.Close
  Err.Clear
End Sub

If restart Then
  ' The updated server asked to be restarted and is exiting: wait for the
  ' port to free up (at most 30 seconds) so the new one can bind to it.
  waited = 0
  Do While Pinging() And waited < 30000
    WScript.Sleep 500
    waited = waited + 500
  Loop
  If Pinging() Then Note "restart: the previous server still answers on port " & port & " after 30 s; starting anyway"
End If

running = Pinging()

If Not running Then
  ' Run the normal start script hidden (window style 0), output to server.log.
  ' DLPCHECK_HIDDEN tells the script it is already running silently.
  sh.Environment("PROCESS")("DLPCHECK_HIDDEN") = "1"
  sh.CurrentDirectory = dir
  sh.Run "cmd /c """"" & dir & "\START_Zscaler_Assessment.bat"" > """ & logPath & """ 2>&1""", 0, False
  If Err.Number <> 0 Then
    Note "could not run START_Zscaler_Assessment.bat: " & Err.Description
    Err.Clear
  End If
  ' Wait until the server answers (at most 30 s) rather than a fixed 4 s:
  ' a first start on a slow laptop (antivirus scanning a fresh Python)
  ' takes longer, and the server writes ui_token.txt before it listens,
  ' so once it answers the token file is the new one, never a stale copy.
  waited = 0
  Do While Not Pinging() And waited < 30000
    WScript.Sleep 500
    waited = waited + 500
  Loop
  If Not Pinging() Then Note "the server did not answer on port " & port & " within 30 s; see server.log"
End If

If restart Or sh.Environment("PROCESS")("ZSCALER_OPEN_BROWSER") = "0" Then
  If Not Pinging() Then Note "restart: the server did not answer on port " & port & " within 30 s of the start; see server.log"
  WScript.Quit 0
End If

' The server writes its UI token to ui_token.txt (owner-only); open the
' browser with it so this browser is unlocked and any other caller is not.
Dim tokenPath, token, tf
tokenPath = dir & "\ui_token.txt"
token = ""
If fso.FileExists(tokenPath) Then
  Set tf = fso.OpenTextFile(tokenPath, 1)
  token = Trim(tf.ReadAll)
  tf.Close
End If
Err.Clear
If token <> "" Then
  sh.Run "http://localhost:" & port & "/?token=" & token, 1, False
Else
  sh.Run "http://localhost:" & port & "/", 1, False
End If
If Err.Number <> 0 Then
  Note "could not open the browser: " & Err.Description & " (open http://localhost:" & port & "/ yourself)"
  Err.Clear
End If
