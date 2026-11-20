@echo off
setlocal
chcp 65001 >nul
if not defined CLAUDE_DIR set "CLAUDE_DIR=%USERPROFILE%\.claude"
py -3 "%CLAUDE_DIR%\tools\review_scan.py" %*
