# Basic Zeek script for learning

module Local;

export {
    redef enum Log::ID += { LogLocal };
}

event zeek_init() {
    print "Zeek learning scaffold loaded: local.zeek";
}

event connection_state_remove(c: connection) {
    if ( c?$history )
        print "connection removed:", c$id$orig_h, c$id$resp_h, c$id$orig_p, c$id$resp_p, c$history;
}
