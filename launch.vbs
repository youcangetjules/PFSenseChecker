' NetCheck silent GUI launcher — no console window.
' Double-click this file (or run via pfsense.bat) to see only the splash.
Option Explicit

Dim sh, fso, root, pyw, mainw, cmd, i, arg

Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
root = fso.GetParentFolderName(WScript.ScriptFullName)
pyw = root & "\.venv\Scripts\pythonw.exe"
mainw = root & "\main.pyw"

If Not fso.FileExists(pyw) Then
  ' First-time setup needs a console briefly.
  sh.Run "cmd /c """ & root & "\pfsense.bat"" setup", 1, True
End If

If Not fso.FileExists(pyw) Then
  MsgBox "NetCheck setup failed — virtual environment not found." & vbCrLf & _
         "Run pfsense.bat setup once, then try again.", 16, "NetCheck"
  WScript.Quit 1
End If

If Not fso.FileExists(mainw) Then
  MsgBox "Missing main.pyw in:" & vbCrLf & root, 16, "NetCheck"
  WScript.Quit 1
End If

cmd = """" & pyw & """ """ & mainw & """"
For i = 0 To WScript.Arguments.Count - 1
  arg = WScript.Arguments(i)
  cmd = cmd & " """ & arg & """"
Next

' WindowStyle 0 = hidden (no console). False = do not wait.
sh.CurrentDirectory = root
sh.Run cmd, 0, False
