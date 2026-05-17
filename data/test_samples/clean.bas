Attribute VB_Name = "Module1"
' Clean VBA module: simple worksheet helper. No auto-exec, no shell, no IO.

Option Explicit

Public Function SumColumn(ws As Worksheet, col As Long) As Double
    Dim lastRow As Long
    lastRow = ws.Cells(ws.Rows.Count, col).End(xlUp).Row
    SumColumn = WorksheetFunction.Sum(ws.Range(ws.Cells(2, col), ws.Cells(lastRow, col)))
End Function

Public Sub FormatHeader(ws As Worksheet)
    Dim header As Range
    Set header = ws.Range("A1:Z1")
    header.Font.Bold = True
    header.Interior.Color = RGB(220, 230, 241)
End Sub

Public Function GreetUser() As String
    GreetUser = "Hello, " & Application.UserName
End Function
