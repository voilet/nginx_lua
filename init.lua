require 'config'
local match = string.match
local ngxmatch=ngx.re.find
-- local ngxmatch=ngx.re.match--
local unescape=ngx.unescape_uri
local get_headers = ngx.req.get_headers
local optionIsOn = function (options) return options == "on" and true or false end
logpath = logdir
rulepath = RulePath
UrlDeny = optionIsOn(UrlDeny)
PostCheck = optionIsOn(postMatch)
CookieCheck = optionIsOn(cookieMatch)
WhiteCheck = optionIsOn(whiteModule)
PathInfoFix = optionIsOn(PathInfoFix)
attacklog = optionIsOn(attacklog)
CCDeny = optionIsOn(CCDeny)
Redirect=optionIsOn(Redirect)

--lua waf syslog
syslogserver='192.168.8.59'
filext=''
local bit = require "bit"
local ffi = require "ffi"
local C = ffi.C
local bor = bit.bor
ffi.cdef[[
int write(int fd, const char *buf, int nbyte);
int open(const char *path, int access, int mode);
int close(int fd);
]]

local O_RDWR   = 0X0002;
local O_CREAT  = 0x0040;
local O_APPEND = 0x0400;
local S_IRUSR = 0x0100;
local S_IWUSR = 0x0080;
function write(logfile,msg)
            local logger_fd = C.open(logfile, bor(O_RDWR, O_CREAT, O_APPEND), bor(S_IRUSR,S_IWUSR));
            local c = msg;
            C.write(logger_fd, c, #c);
            C.close(logger_fd)
end
function syslog(msg)
    ngx.header.content_type = "text/html"
local sock = ngx.socket.udp()
local ok, err = sock:setpeername(syslogserver, 5144)

if not ok then
    ngx.say("failed to connect to syslog server: ", err)
    return
end
ok, err = sock:send(msg)
sock:close()
end
--上面的ip和端口就是syslog server的ip和端口地址，可自行修改
-- debug调试模式
local debug = ngx.config.debug

function Split(szFullString, szSeparator)
    local nFindStartIndex = 1
    local nSplitIndex = 1
    local nSplitArray = {}
    while true do
       ngx.say(szFullString)
       local nFindLastIndex = string.find(szFullString, szSeparator, nFindStartIndex)
       ngx.say(nFindLastIndex)
       if not nFindLastIndex then
        nSplitArray[nSplitIndex] = string.sub(szFullString, nFindStartIndex, string.len(szFullString))
        break
       end
       nSplitArray[nSplitIndex] = string.sub(szFullString, nFindStartIndex, nFindLastIndex - 1)
       nFindStartIndex = nFindLastIndex + string.len(szSeparator)
       nSplitIndex = nSplitIndex + 1
	break
    end
    return "nSplitArray"
end

function getClientIp()
        IP = ngx.var.http_x_forwarded_for
        -- IP = ngx.req.get_headers()["X-Forward-For"]
        if IP == nil then
                IP  = ngx.var.remote_addr
        end
        if IP == nil then
               IP  = "unknown"
        end
        return IP
end
function write(logfile,msg)
    local fd = io.open(logfile,"ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end

function log(method,url,data,ruletag)
    if attacklog then
            local realIp = getClientIp()
            local ua = ngx.var.http_user_agent
        servername=ngx.var.host
        if servername == nil then
		servername = "unknown"
	end
        -- local servername=ngx.var.host
        local time=ngx.localtime()
            if ua  then
                    line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\"  \""..ua.."\" \""..ruletag.."\"\n"
                    syslog_line =  realIp.."  "..time.."  "..method.."  " ..servername.. " "..servername..url.."  "..data.."  "..ua.."  "..ruletag.. " "
                    syslog(syslog_line)
        else
                line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\" - \""..ruletag.."\"\n"
                syslog_line = realIp.."  "..time.."  "..method.."  " ..servername.. " "..servername..url.."  "..data.."  "..ua.. "  " ..ruletag.." "
                syslog(syslog_line)
        end
            local filename = logpath..'/'..servername.."_"..ngx.today().."_sec.log"
        write(filename,line)
    end
end
------------------------------------规则读取函数-------------------------------------------------------------------
function read_rule(var)
    file = io.open(rulepath..'/'..var,"r")
    if file==nil then
        return
    end
    t = {}
    for line in file:lines() do
        table.insert(t,line)
    end
    file:close()
    return(t)
end

urlrules=read_rule('url')
argsrules=read_rule('args')
uarules=read_rule('user-agent')
wturlrules=read_rule('whiteurl')
postrules=read_rule('post')
ckrules=read_rule('cookie')


function say_html()
    if Redirect then
        ngx.header.content_type = "text/html"
        ngx.say(html)
        ngx.exit(200)
    end
end

function whiteurl()
    if WhiteCheck then
        if wturlrules ~=nil then
            for _,rule in pairs(wturlrules) do
                if ngxmatch(ngx.var.request_uri,rule,"imjo") then
                    return true
                 end
            end
        end
    end
    return false
end

function args()
    for _,rule in pairs(argsrules) do
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            if type(val)=='table' then
                if val == false then
                    data=table.concat(val, " ")
                end
            else
                data=val
            end
            if data and type(data) ~= "boolean" and rule ~="" and ngxmatch(unescape(data),rule,"imjo") then
                log('GET',ngx.var.request_uri,"-",rule)
                say_html()
                return true
            end
        end
    end
    return false
end


function url()
    if UrlDeny then
        for _,rule in pairs(urlrules) do
            if rule ~="" and ngxmatch(ngx.var.request_uri,rule,"imjo") then
                log('GET',ngx.var.request_uri,"-",rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _,rule in pairs(uarules) do
            if rule ~="" and ngxmatch(ua,rule,"imjo") then
                log('UA',ngx.var.request_uri,"-",rule)
                say_html()
            return true
            end
        end
    end
    return false
end
function body(data)
    for _,rule in pairs(postrules) do
        if rule ~="" and data~="" and ngxmatch(unescape(data),rule,"imjo") then
            log('POST',ngx.var.request_uri,data,rule)
            say_html()
            return true
        end
    end
    return false
end
function cookie()
    local ck = ngx.var.http_cookie
    if CookieCheck and ck then
        for _,rule in pairs(ckrules) do
            if rule ~="" and ngxmatch(ck,rule,"imjo") then
                log('Cookie',ngx.var.request_uri,"-",rule)
                say_html()
            return true
            end
        end
    end
    return false
end

function denycc()
    if CCDeny then
        local uri=ngx.var.uri
        CCcount=tonumber(string.match(CCrate,'(.*)/'))
        CCseconds=tonumber(string.match(CCrate,'/(.*)'))
        local token = getClientIp()..uri
        local limit = ngx.shared.limit
        local req,_=limit:get(token)
        if req then
            if req > CCcount then
                 ngx.exit(403)
                return true
            else
                 limit:incr(token,1)
            end
        else
            limit:set(token,1,CCseconds)
        end
    end
    return false
end

function get_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end

    local m = match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end

    return match(header, ";%s*boundary=([^\",;]+)")
end

function whiteip()
    if next(ipWhitelist) ~= nil then
        for _,ip in pairs(ipWhitelist) do
            if getClientIp()==ip then
                return true
            end
        end
    end
        return false
end

function blockip()
     if next(ipBlocklist) ~= nil then
         for _,ip in pairs(ipBlocklist) do
             if getClientIp()==ip then
                 ngx.exit(403)
                 return true
             end
         end
     end
         return false
end
