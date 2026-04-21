export const SINGLE_SAMPLES = {
  syslog: `Jun 10 14:23:01 webserver01 sshd[1234]: Failed password for root from 103.45.67.89 port 58321`,
  rfc5424: `<34>1 2026-04-18T19:42:21Z firewall-1 sshd 1024 - - Failed password for invalid user admin from 192.168.1.45 port 51422 ssh2`,
  vpc_flow: `2 123456789 eni-abc123 103.45.67.89 10.0.1.5 45231 443 6 3200 160000 1745000401 1745000430 ACCEPT OK`,
  snmp: `SNMP Trap: authenticationFailure from 10.0.0.5`,
  web: `192.168.1.10 - - [18/Apr/2026:19:42:21 +0000] "GET /admin HTTP/1.1" 401 512`,
  firewall: `DENY TCP from 192.168.1.100 to 10.0.0.5 port 22`,
  windows: `EventID=4625 AccountName=admin FailureReason=Bad password SourceIP=192.168.1.50`,
  dns: `DNS Query from 192.168.1.20 for suspicious-domain.xyz`,
}

export const BATCH_ATTACK_SCENARIO = `Jun 10 14:23:01 webserver01 sshd[1234]: Failed password for root from 103.45.67.89 port 58321
Jun 10 14:23:02 webserver01 sshd[1234]: Failed password for admin from 103.45.67.89 port 58322
Jun 10 14:23:03 webserver01 sshd[1234]: Failed password for root from 103.45.67.89 port 58323
Jun 10 14:23:04 webserver01 sshd[1234]: Failed password for user from 103.45.67.89 port 58324
Jun 10 14:23:05 webserver01 sshd[1234]: Failed password for root from 103.45.67.89 port 58325
Jun 10 14:23:06 webserver01 sshd[1234]: Accepted password for deploy from 192.168.1.5 port 22
2 123456789 eni-abc123 103.45.67.89 10.0.1.5 45231 443 6 3200 160000 1745000401 1745000430 ACCEPT OK
2 123456789 eni-abc123 103.45.67.89 10.0.1.5 45232 443 6 3100 150000 1745000402 1745000431 ACCEPT OK
2 123456789 eni-abc123 103.45.67.89 10.0.1.5 45233 443 6 3050 140000 1745000403 1745000432 ACCEPT OK
2 123456789 eni-abc123 103.45.67.89 10.0.1.5 45234 443 6 3000 130000 1745000404 1745000433 ACCEPT OK
2 123456789 eni-abc123 103.45.67.89 10.0.1.5 45235 443 6 2950 120000 1745000405 1745000434 ACCEPT OK
2 123456789 eni-abc123 103.45.67.89 10.0.1.5 45236 443 6 2900 110000 1745000425 1745000455 ACCEPT OK
2 123456789 eni-abc123 10.0.0.8 10.0.1.5 40000 22 6 50 2000 1745000415 1745000416 REJECT OK
2 123456789 eni-abc123 10.0.0.8 10.0.1.5 40001 22 6 45 1800 1745000416 1745000417 REJECT OK
2 123456789 eni-abc123 10.0.0.8 10.0.1.5 40002 22 6 40 1700 1745000417 1745000418 REJECT OK
SNMP Trap: linkDown from 192.168.1.1
SNMP Trap: linkDown from 192.168.1.1
SNMP Trap: linkDown from 192.168.1.1
SNMP Trap: authenticationFailure from 10.0.0.5
DENY TCP from 192.168.1.100 to 10.0.0.5 port 22
DENY TCP from 192.168.1.100 to 10.0.0.5 port 80
DENY TCP from 192.168.1.100 to 10.0.0.5 port 443`

export const LOG_TYPES = [
  { value: 'syslog',   label: 'Syslog (Legacy)',   icon: '⬛' },
  { value: 'rfc5424',  label: 'RFC 5424 Syslog',   icon: '🔷' },
  { value: 'vpc_flow', label: 'VPC Flow Logs',      icon: '☁️' },
  { value: 'snmp',     label: 'SNMP Trap',          icon: '📡' },
  { value: 'web',      label: 'Apache / Nginx',     icon: '🌐' },
  { value: 'firewall', label: 'Firewall Logs',      icon: '🔥' },
  { value: 'windows',  label: 'Windows Event Logs', icon: '🪟' },
  { value: 'dns',      label: 'DNS Query Logs',     icon: '🔎' },
]

export const SEV_CONFIG = {
  CRITICAL: { color:'text-red-400',    bg:'bg-red-500/15',    border:'border-red-500/30',    dot:'bg-red-400',    glow:'shadow-red-500/20'    },
  HIGH:     { color:'text-orange-400', bg:'bg-orange-500/15', border:'border-orange-500/30', dot:'bg-orange-400', glow:'shadow-orange-500/20' },
  MEDIUM:   { color:'text-yellow-400', bg:'bg-yellow-500/15', border:'border-yellow-500/30', dot:'bg-yellow-400', glow:'shadow-yellow-500/20' },
  LOW:      { color:'text-blue-400',   bg:'bg-blue-500/15',   border:'border-blue-500/30',   dot:'bg-blue-400',   glow:'shadow-blue-500/20'   },
  INFO:     { color:'text-slate-400',  bg:'bg-slate-500/10',  border:'border-slate-600/20',  dot:'bg-slate-400',  glow:''                     },
}
