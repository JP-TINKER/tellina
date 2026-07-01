#!/usr/bin/env bash
# One-time enable: clamav-daemon + group membership for instant scans.
set -euo pipefail

echo "Installing clamav-daemon..."
sudo apt-get install -y clamav-daemon

echo "Adding $USER to clamav group..."
sudo usermod -aG clamav "$USER"

echo "Enabling freshclam -> clamd reload..."
if grep -q '^NotifyClamd no' /etc/clamav/freshclam.conf 2>/dev/null; then
  sudo sed -i 's/^NotifyClamd no/NotifyClamd \/etc\/clamav\/clamd.conf/' /etc/clamav/freshclam.conf
elif ! grep -q '^NotifyClamd' /etc/clamav/freshclam.conf 2>/dev/null; then
  echo 'NotifyClamd /etc/clamav/clamd.conf' | sudo tee -a /etc/clamav/freshclam.conf >/dev/null
fi

echo "Starting daemons..."
sudo systemctl enable --now clamav-daemon clamav-freshclam

echo "Restarting download watcher..."
systemctl --user daemon-reload
systemctl --user restart download-security.service

echo ""
echo "Done. Log out and back in (or reboot) so your session has the clamav group."
echo "Then confirm:  groups | grep clamav"
echo "The watcher calls clamdscan --fdpass directly (no sg). Until re-login it uses clamscan."
echo ""
systemctl is-active clamav-daemon clamav-freshclam
systemctl --user is-active download-security.service
journalctl --user -u download-security.service -n 2 --no-pager
