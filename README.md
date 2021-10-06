# ces-soc-zeek-http_post_bodies

## Purpose

This module is a fork of the [Corelight post_bodies package](https://github.com/corelight/log-add-http-post-bodies). It increases the number of bytes to capture and adds flexibility to control post_body data logging. A use case would be to handle post_bodies with credentials differently than other post_bodies. We do not recommend running both this package and the Corelight package concurrently as unexpected results may occur and performs duplicate work. This code was specifically written to work with Corelight.

## Installation/Upgrade

This script was written and tested using Bro 2.5.x and 3.0.11.
NOTE: Testing TODO on Zeek 4.0+

This is easiest to install through the Zeek package manager:

	zkg refresh
	zkg install https://github.com/nturley3/zeek-http-post-bodies

If you need to upgrade the package:

	zkg refresh
	zkg upgrade https://github.com/nturley3/zeek-http-post-bodies

See the [Zeek Package Manager Docs](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html) for more information.

## Configuration

By default the package will capture the first 1024 bytes of a post_body. You can adjust this by modifying the values of http_post_body_length in scripts/post-body.zeek

## Generated Outputs

This package adds a post_body field to the HTTP log and creates a separate log called http_post.log

## Usage

Typically http logs from other sources, such as a web server, do not log the post_body. However, many security events occur over post_body, such as SQL injection, remote code execution, file uploads, etc. However, this data can also expose sensitive, private, or classified data. By having two log streams, it gives analysts the flexibility to filter such data, or send it to a system with more restrictions or auditing.


