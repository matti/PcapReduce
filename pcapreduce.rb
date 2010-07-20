#!/usr/bin/env ruby1.9.1
require 'packetfu'
require 'net/dns/packet'
require 'net/dns/resolver'
require 'uri'
require 'optiflag'

module PcapReduce extend OptiFlagSet
  optional_flag "o"
  and_process!
end

HttpMethods = ["OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT"]


def http_string(re, pkt)
  lines = pkt.to_s.split("\n")
  lines.map do |l|
    re.match(l).to_s
  end
end

@packets = {}
@selected = []
@cache = []

def store_result(ra, pkt)
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

  if (pkt.tcp_seq == xyz[:next_seq] || xyz[:next_seq].nil?) then
    xyz[:body] += pkt.tcp_header.body 
  end

  xyz[:next_seq] = pkt.tcp_seq + pkt.tcp_header.body.size

  @packets[pkt.tcp_ack] = xyz

  x = yield(xyz[:body])
  store_result(x, pkt)
end

def http(pkt, &fn) 
  if pkt.is_tcp? then
    if (pkt.tcp_dport == 80) || (pkt.tcp_sport == 80) then
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
    content_type = /^Content-Type: (image\/.*)\n/i.match(pkt.to_s)
    if content_type then
      c = pkt.to_s
      image_data = /\n\r?\n(.*)/m.match(c)
      unless image_data.nil? then
        begin
          source = @resolver.send(p.ip_saddr.to_s).answer[0]
        rescue Net::DNS::Resolver::NoResponseError
          puts "unable to resolve: #{p.ip_saddr}"
        end
        source_name = source.nil? ? p.ip_saddr : source.ptr.chomp('.')

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
    []
  }
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

@resolver = Net::DNS::Resolver.new({:udp_timeout=>0.1})
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
    http(p) { |pkt| http_string(/.*HTTP.*/,pkt) }
    http(p) { |pkt| http_string(/^Host:.*/,pkt) }
    http(p) { |pkt| http_string(/(#{HttpMethods.join("|")}).*/,pkt) }
    http(p) { |pkt| http_string(/^User-Agent:.*/i,pkt) }
    http(p) { |pkt| http_string(/password.*/i,pkt) }
    http(p) { |pkt| http_string(/^Host:.*facebook.*/,pkt) }
    http(p) { |pkt| http_string(/^Host:.*fbcdn.*/,pkt) }
    http(p) { |pkt| http_string(/^(Set-)?Cookie:.*utm.*/,pkt) }
    http(p) { |pkt| http_string(/^(Set-)?Cookie:.*JSESSIO.*/,pkt) }
    http(p) { |pkt| http_string(/^Accept.*/,pkt) }
    http(p) { |pkt| http_string(/^(Set-)?Cookie:.*/,pkt) }
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

