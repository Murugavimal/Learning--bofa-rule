# Learning--bofa-rule


when CLIENT_ACCEPTED {
    set static::allowed_domains {
        example.sharepoint.com
        example2.sharepoint.com
        ex3.sharepoint.com
    }
}

# Handle HTTP Requests
when HTTP_REQUEST {
    set host [string tolower [HTTP::host]]
    set allowed 0

    foreach domain $static::allowed_domains {
        if { $host ends_with $domain } {
            set allowed 1
            break
        }
    }

    if { $allowed == 0 } {
        log local0. "REJECT HTTP -> $host blocked"
        reject
    }
}

# Handle HTTPS CONNECT tunneling
when SERVER_CONNECTED {
    set sni [string tolower [SSL::servername]]

    if { $sni eq "" } {
        return
    }

    set allowed 0
    foreach domain $static::allowed_domains {
        if { $sni ends_with $domain } {
            set allowed 1
            break
        }
    }

    if { $allowed == 0 } {
        log local0. "REJECT HTTPS -> $sni blocked"
        reject
    }
}