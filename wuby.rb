#!/usr/bin/ruby -w
# $Id: wuby,v 0.1 2007/09/17 18:00:00 
#
# Wuby = Ruby Web Server designed for light-weight Ruby web applications
# http://www.wuby.org
#
# Copyright (C) 2007  Chris Matthieu <chris@matthieu.us>
#
# Portions of HTTPD version 1.8 were used thanks to contributions from:
# Copyright (C) 2000-2004  Michel van de Ven <hipster@xs4all.nl> 
# Copyright (C) 2004  Patric Mueller <bhaak@gmx.net>
# Reference: http://www.xs4all.nl/~hipster/lib/ruby/httpd
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# ToDo:
# - bug: http://domain/directory//page.html confuses relative links


require "socket"
require "thread"
require "cgi"
require 'erb'
require 'sdbm'


REVISION = 0.3

###########################################################################
# modify this to suit your setup and needs
###########################################################################

# "0.0.0.0" to serve everybody
HOST = "0.0.0.0"
PORT = 8080

# number of simultaneous handler threads
THREADS = 4

# root of the html tree
#DOCROOT = File.expand_path("~/lib/html")
#CLM added working directory support
DOCROOT = Dir.getwd

# location of the logfile; nil = don't log anything
#LOGFILE = File.expand_path("~/lib/html/wuby.log")
#CLM added working directory support
LOGFILE = Dir.getwd + "/wuby.log"

# max number of log rotations; if <= 0: don't rotate
# This value is ignored if LOGFILE is nil.
LOGROTATIONS = 8

# if true, log all http headers
VERBOSE_LOG = true

# if true, detach process from terminal
START_AS_DAEMON = false # CLM - remember to change back to true after developing

# if true, allow anonymous directory browsing
ALLOW_DIR_BROWSE = false 

# change to userids
USER_ID  = 1000
GROUP_ID = 100


###########################################################################
class MimeMap
  def initialize
    @map = Hash.new("*/*")
    #File.foreach("mime.types") { |line|
    #  next if line =~ /^#|^\s*$/
    #  type, extlist = line.chomp.split(/\t+/)
    #  if extlist
    #    extlist.split(/ /).each { |ext| @map[ext] = type }
    #  end
    #}
    
    @map["rhtml"] = "text/html"
    @map["htm"] = "text/html"
    @map["html"] = "text/html"
    @map["mov"] = "video/quicktime"
    @map["css"] = "text/css"
    @map["jpeg"] = "image/jpeg"
    @map["jpg"] = "image/jpeg"
    @map["png"] = "image/jpeg"
    @map["gif"] = "image/gif"
    @map["tif"] = "image/tiff"
    @map["mp3"] = "audio/mpeg"
    @map["xhtml"] = "application/xhtml+xml"
    @map["js"] = "application/x-javascript"
    @map["swf"] = "application/x-shockwave-flash"
    @map["xml"] = "text/xml"
    @map["xsl"] = "text/xml"
    
  end

  def typeof ext
    @map[ext]
  end
end

###########################################################################
class Log
  if LOGFILE.nil?
    def Log.open(stream = nil) end
    def Log.puts(txt) end
    def Log.close() end
  else
    def Log.open stream = LOGFILE
      unless stream.is_a?(IO)
        if LOGROTATIONS > 0
          if test(?f, LOGFILE)
            (LOGROTATIONS - 1).downto(0) { |n|
              target = "#{LOGFILE}.#{n}"
              if test(?f, target)
                File.rename(target, "#{LOGFILE}.#{n + 1}")
              end
            }
            culprit = "#{LOGFILE}.#{LOGROTATIONS}"
            if test(?f, culprit)
              File.delete(culprit)
            end
            File.rename(LOGFILE, "#{LOGFILE}.0")
          end
        end
      end

      begin
        @io = (stream.is_a? IO) ? stream : File.open(stream, "a")
      rescue
        $stderr.puts "wuby: cannot open stream for writing; logging to stderr"
        @io = $stderr
      end
    end

    def Log.close
      @io.close
    end

    def Log.puts txt
      @io.print txt.chomp + "\n"
      @io.flush
    end
  end
end

###########################################################################
class Request
  attr_reader :socket, :header, :method, :file, :mtype, :content, :fatal_error

  def initialize socket, mimemap
  
    @socket = socket
    @header = @method = @file = @content = @mtype = ""
    @fatal_error = false;
    contentlength = 0

    Log.puts "" if VERBOSE_LOG
    begin
      # output from address and time
      if VERBOSE_LOG
        Log.puts "[" + @socket.peeraddr[2..3].join(", ") + "]"
        Log.puts Time.new.to_s
      end

      while (line = @socket.gets) != nil
        break if line == "\r\n" or line == "\n"
        @header << line
        Log.puts line if VERBOSE_LOG
        case line
        when /^(GET|POST) (.*) HTTP\/\d+\.\d+/
          # XXX delay this to the handlers, so they can indicate failures?
          if not VERBOSE_LOG then
            Log.puts "[" + @socket.peeraddr[3] + "] " + line.chomp("\r\n")
          end
          @method = $1
          @file = $2          
        when /^content-length: (\d+)/i
          contentlength = $1.to_i
        end
      end
      if contentlength != 0
        @content = @socket.read contentlength
      end

      #CLM - keep track of current running directory
      #if @file != nil 
      #  $dirstruct = @file 
      #end  
      
      # default to index.rhtml for root and directory requests
      @file = @file + "/index.rhtml" if test(?f, DOCROOT + @file + "/index.rhtml")

      # deduce mimetype from filename suffix
      if @file =~ /\.([a-z]+)$/
        @mtype = mimemap.typeof($1)
      else
        @mtype = "text/plain"
      end
    rescue Exception
      @fatal_error = true;
      Log.puts $!.to_s + "("+$!.class.to_s+")"
    end
  end
end

###########################################################################
class Wuby
  HTTP_200 = "HTTP/1.0 200 OK\n"
  HTTP_404 = "HTTP/1.0 404 Not found\n"

  def initialize
    Log.open
    @hostname = HOST
    @port = PORT
    @mimemap = MimeMap.new
    @socket = TCPserver.new(@hostname, @port)
    change_ids
    @rqueue = Queue.new # request queue, handler threads query this
    @nrequest = 0
    @cgi_mutex = Mutex.new
    ["SIGTERM", "SIGHUP", "SIGINT", "SIGQUIT"].each { |sig|
      trap sig, lambda { shutdown }
    }
  end

  def listen
    
    #CLM
    #!/usr/bin/env ruby -w
    # write pid file to cwd
    pid = File.new("wuby.pid",'w')
    pid.puts($$)
    pid.close
    
    Log.puts "-" * 79 + "\nstart @ " + Time.now.to_s +
        "\nwuby/#{REVISION}; " +
                  "pid #{$$} with #{THREADS} threads listening on #{@hostname}:#{@port}"
    # start handler threads
    Thread.abort_on_exception = true # XXX debugging only?
    THREADS.times { Thread.new { handler } }
    # main accept loop
    loop do
      begin
#        @timein = Time.now
        @rqueue.push @socket.accept
        @nrequest += 1
      rescue
        Log.puts "listener: socket exception: " + $!
      end
    end
        
  end

  private

  def database dbname
    SDBM.new(Dir.getwd + "/" + dbname + ".dbm")
  end
  
  def wrequest(*ios) #CRUD, table, field, id, value 
    db = SDBM.new(Dir.getwd + "/" + ios[1].to_s + ".dbm")

    #get total number of records
    @recordcount = db["count"]
    if @recordcount == nil
      @recordcount = 0
    else
      @recordcount = db["count"].to_i 
    end

    if ios[0].downcase == "c"
      db[ios[2].to_s + "." + @recordcount.to_s] = ios[3].to_s 
      return true
    end

    if ios[0].downcase == "r"
      if db[ios[2].to_s + "." + ios[3].to_s] != nil
        return db[ios[2].to_s + "." + ios[3].to_s]
      else
        return false
      end
    end

    if ios[0].downcase == "u"
      db[ios[2].to_s + "." + ios[3].to_s] = ios[4].to_s
      return true
    end
    
    if ios[0].downcase == "d"
      db.delete(ios[2].to_s + "." + ios[3].to_s)
      return true
    end

    db.close
  end  
  
  def wrecordcount(table)
    db = SDBM.new(Dir.getwd + "/" + table.to_s + ".dbm")
    
    #get total number of records
    @recordcount = db["count"]
    if @recordcount == nil
      @recordcount = 0
    else
      @recordcount = db["count"].to_i 
    end
        
    db.close
    return @recordcount
    
  end
  
  def wrenew(table)
    db = SDBM.new(Dir.getwd + "/" + table.to_s + ".dbm")
    
    #get total number of records
    @recordcount = db["count"]
    if @recordcount == nil
      @recordcount = 0
    else
      @recordcount = db["count"].to_i 
    end

    @recordcount += 1
    db["count"] = @recordcount.to_s
    
    db.close
  end

  def handler
    loop do

      socket = @rqueue.pop
      req = Request.new socket, @mimemap
  
      if not req.fatal_error then

        @timein = Time.now

        @script, param = req.file.split("?")
        @params = nil
        
        if param == nil
          @script = req.file
          @params = nil
        else  
          @params = CGI::parse(param)
          #puts @params["test"]
        end

        if req.method == "POST"
          @params = CGI::parse(req.content)
          #puts @params["memo"]
        end  
       
        puts req.header
        puts req.socket
        puts req.method
        puts req.file
        puts req.mtype
        puts req.content

        #keep current subdirectory structure
        #if @script.scan(/#{$dirstruct}/).length+1 == 1
        #  @script = $dirstruct + @script
        #end
        #puts @script



#TODO fix ENV["HOSTNAME"] - check out envars.rhtml

        ENV["SERVER_SOFTWARE"] = "Ruby-Wuby/#{REVISION}"
        ENV["REMOTE_HOST"] = ENV["HOSTNAME"]
        ENV["REQUEST_METHOD"] = req.method
        ENV["SCRIPT_NAME"] = @script
        ENV["QUERY_STRING"] = param
        ENV["CONTENT_LENGTH"] = req.content.length != 0 ? req.content.length.to_s : nil
        

        if test(?f, DOCROOT + @script)
          handle_file req
        elsif test(?d, DOCROOT + @script)
          if ALLOW_DIR_BROWSE == true
            handle_dir req
          end
        else
          handle_error req
        end

      end
      socket.close
    end
  end


  def handle_dir req
    emit req.socket, HTTP_200 + header("text/html") +
                               "<html>\n<head>\n<title>\nIndex of #{req.file}\n</title>\n</head>\n<body>\n<h1>Index of #{req.file}</h1>\n"
    up = File.expand_path(req.file + "/..", DOCROOT)
    emit req.socket,
         %!<pre><hr /> <a href='#{up}'>Parent Directory</a>\n!
    begin
      dir = Dir.open(DOCROOT + req.file)
      dir.sort.each { |entry|
        next if entry == "." or entry == ".."
        link = entry
        link += "/" if test(?d, DOCROOT + req.file + "/" + link)
        emit req.socket, %! <a href="#{req.file}/#{entry}">#{link}</a>\n!
        #emit req.socket, %! <a href="#{entry}">#{link}</a>\n!
      }
    ensure
      dir.close
    end
    emit req.socket, "</pre><hr>"
    emit req.socket, "<i>Ruby-wuby #{REVISION} at #@hostname:#@port</i></body></html>"
  end

  def handle_file req
    # read file and send it to client
    content = File.open(DOCROOT + @script).read
    
    #CLM logic below added to accommodate for GET query string params and appropriate header
    if req.mtype == "text/plain" and @script.scan(/html+/).length+1
      @mtype = "text/html"
    else
      @mtype = req.mtype
    end

    emit req.socket, HTTP_200 + header(@mtype)
    if @mtype == "text/html"
      emitruby req.socket, content
    else
      emit req.socket, content
    end
  end

  def handle_error req
    emit req.socket, HTTP_404 + header("text/html") +
                               "<h1>404 Not Found</h1>\n" +
                                    "Request header: <pre>#{req.header}</pre>" +
                               "<hr><i>Ruby-Wuby #{REVISION} at #@hostname:#@port</i>"
    Log.puts "404 not found: " + @script + "\n\n"
    # XXX OR
    #     if req.mtype =~ /^text\//
    #       emit req.socket, "HTTP/1.0 404 Not found\n" +
    #         "Content-type: text/html\n\n" +
    #         "<h1>Object not found</h1>\n" +
    #         "Request header: <pre>#{req.header}</pre>"
    #     else
    #       emit req.socket, "HTTP/1.0 404 Not found\n"
    #     end
  end

  def header mimetype
    "Content-type: #{mimetype}\n\n"
    # XXX "Content-type: #{mimetype}\nConnection: close\n\n"
  end

  def emit socket, data
    begin
#      @timing = Time.now - @timein
#      puts @timing.to_s + " seconds"
      socket.write data
    rescue
      Log.puts "emit: socket exception: " + $!
    end 
  end

  def emitruby socket, data
    begin
      datanew = data.gsub(/wrender/, "IO.read")
      template = ERB.new <<-EOF
        #{datanew}
      EOF
      @timing = Time.now - @timein
      puts @timing.to_s + " seconds"
      socket.write template.result(binding)
    rescue
      Log.puts "emit: socket exception: " + $!
    end 
  end


  def change_ids
    #TODO
    #Process.uid  = USER_ID
    #Process.gid  = GROUP_ID
    #Process.euid = USER_ID
    #Process.egid = GROUP_ID
  end

  def shutdown
    @socket.close
    Log.puts "#{@nrequest} requests handled"
    Log.puts "shutdown @ #{Time.now.to_s}"
    Log.close
    exit
  end
end

###########################################################################
# TODO move this into wuby. Provide both a background and foreground func.
def daemon
  if fork == nil
    Process.setsid # create new session, disconnect from tty
    [$stdin, $stdout, $stderr].each { |stream| stream.reopen "/dev/null" }
    Wuby.new.listen
  end
end

#Process switches on launch
i=0
while i <= ARGV.length
  if ARGV[i].to_s == "-h"
    puts "Wuby Help"
    puts "-h     help"
    puts "-v     version"
    puts "-d     daemonize"
    puts "-t     threads followed by number of threads (-t 5)"
    puts "-a     IP address for listening (-a 0.0.0.0)"
    puts "-p     Port number for listening (-p 80)"
    puts "-b     Allows directory browsing"
    puts "-k     Kill Wuby after started with daemon option"
    exit
  end
  if ARGV[i].to_s == "-v"
    puts "Wuby Version = #{REVISION}"
    exit
  end
  if ARGV[i].to_s == "-d"
    START_AS_DAEMON = true
  end
  if ARGV[i].to_s == "-t"
    THREADS = ARGV[i+1].to_s
  end
  if ARGV[i].to_s == "-p"
    PORT = ARGV[i+1].to_s
  end
  if ARGV[i].to_s == "-a"
    HOST = ARGV[i+1].to_s
  end
  if ARGV[i].to_s == "-b"
    ALLOW_DIR_BROWSE = true
  end
  if ARGV[i].to_s == "-k"
    #system("kill `ps aux | grep wuby | grep -v grep | awk '{print $2}'`")
    
    # kill the pid in the wuby.pid file
    f = File.new('wuby.pid','r')
    pid = f.readlines.join.chomp.to_i
    f.close
    puts "Killing wuby running with #{pid}"
    #remove the call to system, and just send term to the pid
    Process.kill "TERM", pid
    File.delete('wuby.pid')  
    
    exit
  end
  i += 1
end
  
if START_AS_DAEMON == false
  #LOGFILE = $stderr # CLM removed line
  puts "Starting webserver on #{HOST}:#{PORT} - single thread"
  puts "Working Directory #{Dir.getwd}"
  Wuby.new.listen
else
  #puts "Starting webserver on #{HOST}:#{PORT} - #{THREADS} threads"
  #puts "Working Directory #{Dir.getwd}"
  #daemon
  
  if File.exists?('wuby.pid')
       puts "pid file exists, are we already running?"
       puts "remove wuby.pid to continue"
  else
       puts "Starting webserver on #{HOST}:#{PORT} - #{THREADS} threads"
       puts "Working Directory #{Dir.getwd}"
       daemon
  end
  
end
