; NSIS installer hooks for the IPsec VPN Client.
;
; Registering the broker creates a Windows service, which needs Administrator
; rights — so this only works because the installer is per-machine (see
; bundle.windows.nsis.installMode) and therefore runs elevated. In Tauri's
; default per-user mode the installer runs unelevated, the registration fails
; with access-denied, and the app — finding no broker — falls back to elevating
; charon-svc itself on every connect (a UAC prompt and a console window).
;
; With the service installed, the (unelevated) app drives charon and DNS through
; the broker over its named pipe, so a connect never raises a UAC prompt.
; Uninstalling removes the service again. The MSI registers the same service
; from a WiX fragment (installer.wxs).

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "Registering the VPN broker service..."
  ; auto-start LocalSystem service; supervises charon-svc + applies VPN DNS.
  nsExec::ExecToLog '"$INSTDIR\vpn-broker.exe" install'
  Pop $0
  DetailPrint "vpn-broker install exit code: $0"
  ; Not fatal — the app still connects through its elevate-charon fallback — but
  ; a silently skipped registration is what leaves every connect asking for
  ; admin, so say it out loud instead of letting the user wonder.
  ${If} $0 != 0
    MessageBox MB_ICONEXCLAMATION|MB_OK "The VPN broker service could not be registered (exit code $0).$\r$\n$\r$\nThe app will still work, but every connect will ask for Administrator rights and open a console window."
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "Removing the VPN broker service..."
  nsExec::ExecToLog '"$INSTDIR\vpn-broker.exe" uninstall'
  Pop $0
  DetailPrint "vpn-broker uninstall exit code: $0"
!macroend
