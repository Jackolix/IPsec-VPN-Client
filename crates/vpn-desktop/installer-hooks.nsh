; NSIS installer hooks for the IPsec VPN Client.
;
; The installer runs elevated, so this is the single place we register the
; privileged broker as a Windows service. Once installed, the (unelevated) app
; drives charon and DNS through the broker over its named pipe, so a connect
; never raises a UAC prompt. Uninstalling removes the service again.

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "Registering the VPN broker service..."
  ; auto-start LocalSystem service; supervises charon-svc + applies VPN DNS.
  nsExec::ExecToLog '"$INSTDIR\vpn-broker.exe" install'
  Pop $0
  DetailPrint "vpn-broker install exit code: $0"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "Removing the VPN broker service..."
  nsExec::ExecToLog '"$INSTDIR\vpn-broker.exe" uninstall'
  Pop $0
  DetailPrint "vpn-broker uninstall exit code: $0"
!macroend
