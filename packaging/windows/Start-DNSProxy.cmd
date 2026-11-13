@echo off
"%~dp0dnsp-modern.exe" -l 127.0.0.1 -l ::1 -p 53 --bootstrap-address 1.1.1.1 --cache-entries 256 -m 9090
if errorlevel 1 pause
