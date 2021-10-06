##! Module to extend the Corelight JSON post body module
## NOTE: This log filter code works fine on Zeek. However, Corelight
## as of v1.15 does not support add and remove filter functions yet. For this
## reason, we are creating a new log stream to handle HTTP POST bodies and
## disabling this script. 

@load base/protocols/http
@load base/utils/urls
# @load base/frameworks/notice

module HTTPPOST;

function json_streaming_post_body_log(id: Log::ID, path: string, rec: HTTP::Info): string
{
    local newpath: string = (rec?$post_body && |rec$post_body| > 0) ? path + "-post" : path;
    
    # It appears when using a predicate function, we can modify the record to be logged
    # In this case, we redact the post bodies with credentials.
    # This was the only way I could find to do something like this
    if(check_for_post_body_redaction(rec))
    {
        rec$post_body="redacted";
    }
    return newpath;
}

function default_post_body_log(id: Log::ID, path: string, rec: HTTP::Info): string
{
    local newpath: string = (rec?$post_body && |rec$post_body| > 0) ? "http-post" : "http";
    # See comment from function above
    if(check_for_post_body_redaction(rec))
    {
        rec$post_body="redacted";
    }
    return newpath;
}

event zeek_init() &priority=-2000
{
    # Removing the default filter here is important since it seems the Corelight json-streaming module
    # sets the default filter to "json-streaming" and default logs will not get written correctly
    # Also in that module, you can set the JSONStreaming::disable_default_logs. When this value is true,
    # only json_streaming_* logs are written and default logs are disabled. If set to false, the default
    # filter name is actually set to "json-streaming" instead of default. The code below handles those differences
    # so this module should also respect the status of JSONStreaming::disable_default_logs

    local default_filter: Log::Filter;
    local filter: Log::Filter;
    # print(Log::get_filter(HTTP::LOG, "default"));

    # Get the current log filter for HTTP::LOG
    local current_filter = Log::get_filter(HTTP::LOG, "default");

    # If the value of JSONStreaming::disable_default_logs = T, then the default filter is overwritten to write json_streaming_* logs
    # only. Therefore, we do the same and adjust the default filter to split the json_streaming_http* logs. 
    if(current_filter$name == "default")
    {
        filter = Log::get_filter(HTTP::LOG, "default");
        if(filter$name != "<not found>" && filter?$path)
        {
            filter$path_func = json_streaming_post_body_log;
            local def_result = Log::add_filter(HTTP::LOG, filter);
        }
    }
    else # The value of JSONStreaming::disable_default_logs = F, therefore update the default AND json_streaming filters. 
    {
        Log::remove_default_filter(HTTP::LOG);
        default_filter = [
            $name="new-default",
            $path_func=default_post_body_log
        ];
        Log::add_filter(HTTP::LOG, default_filter);

        filter = Log::get_filter(HTTP::LOG, "json-streaming");
        if(filter$name != "<not found>" && filter?$path)
        {
            filter$path_func = json_streaming_post_body_log;
            local json_result = Log::add_filter(HTTP::LOG, filter);
        }
    }
}

