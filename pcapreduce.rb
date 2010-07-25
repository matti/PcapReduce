#!/usr/bin/env ruby1.9.1
require 'packetfu'
require 'net/dns/packet'
require 'net/dns/resolver'
require 'uri'
require 'optiflag'
require 'zlib'

module PcapReduce extend OptiFlagSet
  optional_flag "o"
  and_process!
end

HttpMethods = ["OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT"]

def extract_matches(re, all)
  lines = all.split("\n")
  lines.map do |l|
    re.match(l).to_s
  end
end

def body_string(re, pkt)
  body = /\n\r?\n(.*)/m.match(pkt.to_s)
  if body then
    extract_matches(re, body[1])
  end
end

def header_string(re, pkt)
  headers = /(.*)\n\r?\n/m.match(pkt.to_s)
  if headers then
    extract_matches(re, headers[1])
  end
end

def http_string(re, pkt)
  extract_matches(re, pkt.to_s)
end

@packets = {}
@selected = []
@cache = []

def store_result(ra, pkt)
  unless ra.nil? then
    ra.each do |r|
      unless r.empty? then
        @selected << pkt unless @outfile.nil?
        unless @cache.include?(r) then
          @cache << r
          puts URI.unescape(r)
        end
      end
    end
  end
end

def tcp(pkt, port=0)
  if (pkt.is_tcp?) then
    if (port==0 || pkt.tcp_src == port || pkt.tcp_dst == port) then
      s = "ts: #{pkt.ip_saddr}:#{pkt.tcp_src}" 
      d = "td: #{pkt.ip_daddr}:#{pkt.tcp_dst}" 
      store_result([s,d], pkt)
    end
  end
end

def udp(pkt, port=0)
  if (pkt.is_udp?) then
    if (port==0 || pkt.udp_src == port || pkt.udp_dst == port) then
      s = "us: #{pkt.ip_saddr}:#{pkt.udp_src}" 
      d = "ud: #{pkt.ip_daddr}:#{pkt.udp_dst}" 
      store_result([s,d], pkt)
    end
  end
end

def dns(pkt)
  if pkt.is_udp? then
    if (pkt.udp_dport == 53) || (pkt.udp_sport == 53) then
      dns_packet = Net::DNS::Packet::parse(pkt.udp_header.body)
      names = dns_packet.answer.map {|a| a.name}
      names += dns_packet.question.map {|q| q.qName}
      store_result(names, pkt)
    end
  end
end

def data(pkt)
  xyz = @packets[pkt.tcp_ack] || { :body => pkt.tcp_header.body }

  if (pkt.tcp_seq == xyz[:next_seq]) then
    xyz[:body] += pkt.tcp_header.body 
  end

  xyz[:next_seq] = pkt.tcp_seq + pkt.tcp_header.body.size

  @packets[pkt.tcp_ack] = xyz

  x = yield(inflate(xyz[:body]))
  store_result(x, pkt)
end

def http(pkt, &fn) 
  if pkt.is_tcp? then
    pkt_ports = [pkt.tcp_dport, pkt.tcp_sport]
    expected_ports = [80, 8080]
    existing_ports = pkt_ports.select { |port| expected_ports.include? port }
    unless existing_ports.empty? then
      data(pkt, &fn)
    end
  end
end

ImageFiles = { 
  "image/jpeg" => "jpg", 
  "image/jpg" => "jpg", 
  "image/pjpeg" => "jpg", 
  "image/gif" => "gif",
  "image/png" => "png",
  "image/x-icon" => nil
}

def images(p)
  http(p) { |pkt| 
    content_type = /^Content-Type: (image\/[^; \n]*).*\n/i.match(pkt.to_s)
    if content_type then
      c = pkt.to_s
      image_data = /\n\r?\n(.*)/m.match(c)
      if image_data then
        begin
          source = @resolver.send(p.ip_saddr.to_s).answer[0]
        rescue Net::DNS::Resolver::NoResponseError
          puts "unable to resolve: #{p.ip_saddr}"
        end
        source_name = source.respond_to?(:ptr) ? source.ptr.chomp('.') : p.ip_saddr

        file_type = ImageFiles[content_type[1].strip]
        unless file_type.nil? then
          f = File.new("images/#{source_name}-%s.#{file_type}" % p.tcp_ack, "w") 
          f.write(image_data[1])
          f.close
        else 
          puts "ignoring image found.. #{content_type.to_s}"
        end
      end
    end
  }
end

def inflate(pkt)
  gzip_encoded = /^Content-Encoding: gzip\r?\n/i.match(pkt.to_s)
  parts = /(.*\n\r?\n)(.*)/m.match(pkt.to_s)
  if gzip_encoded then
    if parts then
      begin
        gzipped = parts[2]
        inflated = Zlib::GzipReader.new(StringIO.new(gzipped)).read
        inflated.force_encoding "binary" if inflated.respond_to? :force_encoding
        parts[1] + inflated
      rescue Zlib::DataError, Zlib::GzipFile::Error
      end
    end
  else
    pkt.to_s
  end
end

def iterate_packets(file)
  file = File.open(file) {|f| f.read}
  file.force_encoding "binary" if file.respond_to? :force_encoding
  stats = {}
  body = file[24,file.size]

  while body.size > 16 
    p = PacketFu::PcapPacket::new(:endian => :little)
    p.read(body)
    pkt = PacketFu::Packet::parse(p.data) 
    unless pkt.is_invalid? then
      yield(pkt)
    end
    body = body[p.sz,body.size]
  end
end

@resolver = Net::DNS::Resolver.new({:udp_timeout=>1})
@outfile = ARGV.flags.o


puts "Pcaprub version: #{Pcap.version}"

if File.readable?(infile = (ARGV[0] || "in.cap"))
  puts "Packets in '#{infile}'"
  puts "----------------------"
  iterate_packets(infile) { |p| 
    tcp(p, 22)
    images(p)
    udp(p, 53)
    dns(p)
    http(p) { |pkt| http_string(/.*HTTP.*/, pkt) }
    http(p) { |pkt| header_string(/^Host:.*/, pkt) }
    http(p) { |pkt| body_string(/"msg":/i, pkt) }
    http(p) { |pkt| body_string(/<title>.*/mi, pkt) }
    http(p) { |pkt| header_string(/(#{HttpMethods.join("|")}).*/,pkt) }
    http(p) { |pkt| header_string(/^User-Agent:.*/i,pkt) }
    http(p) { |pkt| http_string(/password.*/i,pkt) }
    http(p) { |pkt| http_string(/facebook/i,pkt) }
    http(p) { |pkt| body_string(/login.*/i,pkt) }
    http(p) { |pkt| header_string(/^Host:.*facebook.*/,pkt) }
    http(p) { |pkt| header_string(/^Host:.*fbcdn.*/,pkt) }
    http(p) { |pkt| header_string(/^(Set-)?Cookie:.*utm.*/,pkt) }
    http(p) { |pkt| header_string(/^(Set-)?Cookie:.*JSESSIO.*/,pkt) }
    http(p) { |pkt| header_string(/^Accept.*/,pkt) }
    http(p) { |pkt| header_string(/^Content-Type.*/,pkt) }
    http(p) { |pkt| header_string(/^(Set-)?Cookie:.*/,pkt) }
    http(p) { |pkt| http_string(/http(s)?(:\/\/)?[%a-zA-Z0-9\.\-]*/,pkt) }
  }
  unless @outfile.nil? then
    puts "filtered, writing outfile..."
    outfile = PacketFu::PcapFile::new
    outfile.array_to_file(:array => @selected)
    outfile.write(@outfile)
  end
else
  raise RuntimeError, "Need an infile, like so: #{$0} in.pcap"
end

