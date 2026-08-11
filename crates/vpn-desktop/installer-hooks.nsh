; NSIS installer hooks for the VPN Client.
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

!macro NSIS_HOOK_PREINSTALL
  ; On an upgrade the previous broker service is still running, and it holds a
  ; lock on vpn-broker.exe (and the charon binaries it supervises) — so writing
  ; the new files fails with "file in use". Stop it first; its own shutdown
  ; reverts DNS and stops charon, releasing the locks. The service definition is
  ; left in place, so POSTINSTALL's "install" simply starts it again against the
  ; freshly written binary. A fresh install has no vpn-broker.exe here yet — the
  ; guard skips it, so this is a no-op the first time.
  ${If} ${FileExists} "$INSTDIR\vpn-broker.exe"
    DetailPrint "Stopping the running VPN broker service before upgrade..."
    nsExec::ExecToLog '"$INSTDIR\vpn-broker.exe" stop'
    Pop $0
    DetailPrint "vpn-broker stop exit code: $0"
    ; Give Windows a moment to release the image handles after the process exits.
    Sleep 1000
  ${EndIf}
!macroend

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
