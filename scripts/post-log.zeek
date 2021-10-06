module HTTPPOST;

export {
    redef enum Log::ID += { LOG };
}

# Event that can be handled to access the HTTP record as it is sent on to the logging framework.
event HTTP::log_http(rec: HTTP::Info)
{
    if(rec?$post_body && |rec$post_body| > 0)
    {
        Log::write(HTTPPOST::LOG, rec);
    }
}

event zeek_init()
{
    # Create the new HTTP POST event logging stream (http_post.log)
    local stream = [$columns=HTTP::Info, $path="http_post"];
    Log::create_stream(HTTPPOST::LOG, stream);
}
