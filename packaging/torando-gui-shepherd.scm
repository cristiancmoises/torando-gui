;;; SPDX-License-Identifier: AGPL-3.0-only
;;; Copyright (c) 2026 Cristian Cezar Moisés — AGPL-3.0-only
;;;
;;; Self-contained GNU Shepherd service for running torando-guid on GNU Guix
;;; System.  Guix supervises daemons with the Shepherd, NOT systemd, so the
;;; systemd unit shipped in this package is inert on Guix — use this instead.
;;;
;;; This is the standalone twin of the securityops channel's
;;; (securityops services torando); use whichever fits.  Make the torando-gui
;;; package resolvable first (install it, or add the securityops channel), then
;;; point `guix system' at this file's directory:
;;;
;;;   (use-modules (torando-gui-shepherd))
;;;   (operating-system
;;;     ;; …
;;;     (services (cons* (service torando-gui-service-type)
;;;                      (service tor-service-type)
;;;                      %desktop-services)))
;;;
;;;   guix system reconfigure -L /path/to/torando-gui/packaging config.scm
;;;   herd start torando-gui
;;;
;;; The daemon runs as root (it programs netfilter, pins resolv.conf, edits
;;; torrc), in the foreground with SIGTERM/SIGINT handlers, so the default
;;; kill-destructor stops it cleanly.
;;;
;;; Guix caveat: /etc/tor/torrc is a read-only store symlink owned by
;;; tor-service-type, so turn OFF "manage torrc" in the GUI Settings (it persists
;;; to the writable /etc/torando-gui/config.json) and let tor-service-type own
;;; Tor's config.  Netfilter/DNS-pin/killswitch/status all work normally.

(define-module (torando-gui-shepherd)
  #:use-module (gnu services)
  #:use-module (gnu services shepherd)
  #:use-module (gnu packages)                     ;specification->package
  #:use-module (guix gexp)
  #:use-module (guix records)
  #:export (torando-gui-configuration
            torando-gui-configuration?
            torando-gui-configuration-package
            torando-gui-configuration-host
            torando-gui-configuration-port
            torando-gui-configuration-config-file
            torando-gui-configuration-extra-options
            torando-gui-configuration-seed-config
            torando-gui-service-type))

(define-record-type* <torando-gui-configuration>
  torando-gui-configuration make-torando-gui-configuration
  torando-gui-configuration?
  ;; Package providing bin/torando-guid.  Resolved by name from your channels;
  ;; override with your own package object if you built it some other way.
  (package        torando-gui-configuration-package
                  (default (specification->package "torando-gui")))
  (host           torando-gui-configuration-host           (default "127.0.0.1"))
  (port           torando-gui-configuration-port           (default 8088))
  (config-file    torando-gui-configuration-config-file    (default #f))
  (extra-options  torando-gui-configuration-extra-options  (default '()))
  ;; Initial /etc/torando-gui/config.json, written on activation IF absent (so
  ;; later GUI changes persist).  Default makes the daemon correct on Guix:
  ;; torrc management OFF (tor-service-type owns the read-only /etc/tor/torrc)
  ;; and DNSPort 5353 to match a typical tor-service.  #f to seed nothing.
  (seed-config    torando-gui-configuration-seed-config
                  (default "{\n  \"manage_torrc\": false,\n  \"dns_port\": 5353\n}\n")))

(define (torando-gui-shepherd-service config)
  (let* ((package     (torando-gui-configuration-package config))
         (host        (torando-gui-configuration-host config))
         (port        (torando-gui-configuration-port config))
         (config-file (torando-gui-configuration-config-file config))
         (extra       (torando-gui-configuration-extra-options config))
         (args        (append (list "--host" host
                                    "--port" (number->string port))
                              (if config-file (list "--config" config-file) '())
                              extra)))
    (list
     (shepherd-service
      (documentation "Torando Control: route a local user's egress through Tor \
(transparent proxy + killswitch).")
      (provision '(torando-gui))
      (requirement '(networking))
      (start #~(make-forkexec-constructor
                (cons #$(file-append package "/bin/torando-guid")
                      (list #$@args))
                #:log-file "/var/log/torando-gui.log"))
      (stop #~(make-kill-destructor))
      (respawn? #t)))))

(define (torando-gui-activation config)
  ;; Seed /etc/torando-gui/config.json once (writable, NOT a store symlink) so
  ;; the daemon reads it and the GUI can still save changes back to it.
  (let ((seed (torando-gui-configuration-seed-config config)))
    (if seed
        #~(let ((dir "/etc/torando-gui")
                (file "/etc/torando-gui/config.json"))
            (unless (file-exists? file)
              (unless (file-exists? dir) (mkdir dir))
              (call-with-output-file file
                (lambda (port) (display #$seed port)))
              (chmod file #o644)))
        #~#t)))

(define torando-gui-service-type
  (service-type
   (name 'torando-gui)
   (extensions
    (list (service-extension shepherd-root-service-type
                             torando-gui-shepherd-service)
          (service-extension activation-service-type
                             torando-gui-activation)
          (service-extension profile-service-type
                             (lambda (config)
                               (list (torando-gui-configuration-package config))))))
   (default-value (torando-gui-configuration))
   (description "Run the Torando Control daemon (@command{torando-guid}) under
the GNU Shepherd on Guix System.")))
