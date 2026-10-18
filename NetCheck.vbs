' Shortcut-friendly name — same as launch.vbs (silent splash / no console).
' Single .bat entry point remains pfsense.bat (setup / GUI / tools).
Set fso = CreateObject("Scripting.FileSystemObject")
CreateObject("WScript.Shell").Run _
  "wscript //nologo """ & fso.GetParentFolderName(WScript.ScriptFullName) & "\launch.vbs""", _
  0, False
