# Basic Zeek script for learning

@load base/frameworks/notice

module Local;

export {
    redef enum Log::ID += { LogLocalEvents };

    type Info: record {
        ts: time &log;
        uid: string &log &optional;
        src: addr &log &optional;
        dst: addr &log &optional;
        service: string &log &optional;
        note: string &log;
        details: string &log &optional;
    };

    redef enum Notice::Type += {
        High_Connection_Volume,
        High_DNS_Query_Volume,
        Suspicious_HTTP_URI,
        Unexpected_HTTP_Method
    };

    const conn_threshold = 10 &redef;
    const dns_threshold = 8 &redef;
    const suspicious_uri = /(\.\.\/|select|union|<script|cmd=|\/admin|\/wp-admin|\/login)/ &redef;
}

global conn_counter: table[addr] of count &default=0;
global dns_counter: table[addr] of count &default=0;

function write_local(note: string, details: string, c: connection)
    {
    local rec: Info = [$ts=network_time(), $note=note, $details=details];

    if ( c?$uid )
        rec$uid = c$uid;

    rec$src = c$id$orig_h;
    rec$dst = c$id$resp_h;

    if ( c?$service )
        rec$service = fmt("%s", c$service);

    Log::write(LogLocalEvents, rec);
    }

event zeek_init()
    {
    Log::create_stream(LogLocalEvents, [$columns=Info, $path="local_events"]);
    print "Zeek learning scaffold loaded: local.zeek";
    }

event connection_state_remove(c: connection)
    {
    if ( c?$history )
        print "connection removed:", c$id$orig_h, c$id$resp_h, c$id$orig_p, c$id$resp_p, c$history;

    local src = c$id$orig_h;
    ++conn_counter[src];

    if ( conn_counter[src] == conn_threshold )
        {
        NOTICE([$note=High_Connection_Volume,
                $msg=fmt("source %s crossed %d closed connections", src, conn_threshold),
                $conn=c,
                $src=src]);

        write_local("high_connection_volume",
                    fmt("source %s reached %d closed connections", src, conn_counter[src]),
                    c);
        }
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    local src = c$id$orig_h;
    ++dns_counter[src];

    if ( dns_counter[src] == dns_threshold )
        {
        NOTICE([$note=High_DNS_Query_Volume,
                $msg=fmt("source %s crossed %d DNS requests", src, dns_threshold),
                $conn=c,
                $src=src]);

        write_local("high_dns_query_volume",
                    fmt("source %s reached %d DNS requests", src, dns_counter[src]),
                    c);
        }
    }

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    local method_l = to_lower(method);
    local uri_l = to_lower(unescaped_URI);

    if ( method_l != "get" && method_l != "post" && method_l != "head" )
        {
        NOTICE([$note=Unexpected_HTTP_Method,
                $msg=fmt("unexpected HTTP method %s on %s", method, unescaped_URI),
                $conn=c]);

        write_local("unexpected_http_method", fmt("%s %s", method, unescaped_URI), c);
        }

    if ( suspicious_uri in uri_l )
        {
        NOTICE([$note=Suspicious_HTTP_URI,
                $msg=fmt("suspicious URI %s", unescaped_URI),
                $conn=c]);

        write_local("suspicious_http_uri", unescaped_URI, c);
        }
    }
