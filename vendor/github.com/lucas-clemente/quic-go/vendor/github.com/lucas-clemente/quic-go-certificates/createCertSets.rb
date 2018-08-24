#!/usr/bin/env ruby
#
# Extract the common certificate sets from the chromium source to go
#
# Usage:
# createCertSets.rb 1 ~/src/chromium/src/net/quic/crypto/common_cert_set_1*
# createCertSets.rb 2 ~/src/chromium/src/net/quic/crypto/common_cert_set_2*

n = ARGV.shift
mainFile = ARGV.shift
dataFiles = ARGV

data = "package certsets\n"
data += File.read(mainFile)
data += (dataFiles.map{|p| File.read(p)}).join

# Good enough
data.gsub!(/\/\*(.*?)\*\//m, '')
data.gsub!(/^#include.+/, '')
data.gsub!(/^#if 0(.*?)\n#endif/m, '')

data.gsub!(/^static const size_t kNumCerts.+/, '')
data.gsub!(/static const size_t kLens[^}]+};/m, '')

data.gsub!('static const unsigned char* const kCerts[] = {', "var CertSet#{n} = [][]byte{")
data.gsub!('static const uint64_t kHash = UINT64_C', "const CertSet#{n}Hash uint64 = ")

data.gsub!(/static const unsigned char kDERCert(\d+)\[\] = /, "var kDERCert\\1 = []byte")

data.gsub!(/kDERCert(\d+)/, "certSet#{n}Cert\\1")

File.write("cert_set_#{n}.go", data)

system("gofmt -w -s cert_set_#{n}.go")
