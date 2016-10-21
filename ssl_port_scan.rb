#!/usr/bin/env ruby

#
# ssl_port_scan
#
#   This script looks at all tcp ports > 80 and extracts the cert details in case the ports are taking SSL traffic
#
#   The following fields are extracted:
#     Cert Issuer
#     Cert Expiry Date
#     Subject Alternative Names
#
#   In addition to the above, the name and PID of the process behind the port are also included the output.
#

require 'date'
require 'time'

ss_output = %x(ss -tlnp)
count = 0
if $?.success?
  ss_output.each do |line|
    next if line.match(/^LISTEN/).nil?
    fields = line.split(' ')
    #
    # sample output: ["LISTEN", "0", "5", "*:53", "*:*", "users:((\"dnsmasq\",75298,5))"]
    #
    port = fields[3].split(':')[-1].to_i
    process = fields[5].split('"')[1].split('\\')[0]
    pid     = fields[5].split(',')[1]
    next if port <= 80
    cert_info = %x(echo | timeout 5 openssl s_client -connect localhost:#{port} 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | openssl x509 -text 2>/dev/null)
    if $?.success?
      expect_san = false
      issuer = expiry_date = san = nil
      cert_info.each do |cert_line|
        if cert_line.match(/^\s+Issuer:/)
          issuer = cert_line.split(', O=')[1].split(', OU=')[0]
        elsif cert_line.match(/^\s+Not After\s*:\s*/)
          #
          # Get expiry time in PDT
          #
          s = cert_line.split(/Not After\s*:/)[1].strip
          expiry_date = (Time.parse(DateTime.parse(s).strftime("%Y-%m-%d %H:%M:%S %Z").to_s).utc + Time.zone_offset("PDT")).strftime("%Y-%m-%d %H:%M:%S")
        elsif cert_line.match(/^\s+X509v3 Subject Alternative Name:/)
          expect_san = true
        elsif expect_san
          san = cert_line.strip
          expect_san = false
        end
      end

      puts "port=#{port}|process=#{process}|issuer=#{issuer}|expiry=#{expiry_date}|san=#{san}|"
      count += 1
    end
  end
  if count == 0
    puts "No SSL"
  end
  exit 0
else
  puts "ERROR: unable to get list of ports"
  exit 5
end
