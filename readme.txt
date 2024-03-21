The intention of this program is to monitor (= periodically poll) for changes in DNS records
and notify any configured service thats interested

We'll be starting off with the following sinks/listeners:
    * Traefik whitelist, internal ip should contain our own external ip
    * Traefik whitelist, letsencrypt ip? (should be a better way, ok for now)
    
    * Pushover, our public ip changes -> get mad at ISP
    * Transip api, our public ip changes -> any A records pointing to said ip should be updated