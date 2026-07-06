# App-Geshtinanna

idea so far... 



## suricata 

Uses a flows dir or `/var/log/suricata/flows/current/`. And that each eve flow type log is it's own.

Use Algorithm::Time::ToNumber->suricata_to_circle_both for converting the desired time tield to something that can be used with Isolation Forest.

Algorithm::EventsPerSecond is used for tracking events per second for stuff.

Sets are added under the slug of suricata.

### flow

one set ...

set flow

| column | description
|-|-|
| flow.pkts_toserver | raw flow.pkts_toserver |
| flow.pkts_toserver | raw flow.pkts_toserver |
| flow.bytes_toserver | raw flow.bytes_toserver |
| flow.bytes_toserver | raw flow.bytes_toserver |
| duration | derived from flow.end - flow.start |
| proto | encoded proto|
| proto | encoded proto |
| dest_port | encoded based on if it is well known or not |
| bytes_to_packets | bytes to packet ratio |
| up_to_down | upload to download ration |

### dns

Two sets... the with time includes

set dns_with_time

| column | description |
|-|-|
| time_sin | timestamp sin angle |
| time_cos | timestamp cos angle |
| domain | Shannon entropy of the queried domain (DGA detection) |
| rrtype | encoded rrtype |
| rcode | rate per client |
| ttl | ttl value for the response |

set dns

| column | description |
|-|-|
| time_sin | timestamp sin angle |
| time_cos | timestamp cos angle |
| domain | Shannon entropy of the queried domain (DGA detection) |
| rrtype | encoded rrtype |
| rcode | rate per client |
| ttl | ttl value for the response |

#### http

| column | description |
|-|-|
|length| body size|
|http_method|encoded http_method|
|url_length|URL length|
|url_path_depth|path depth of the url|
|url_non_numeric|count of non-numeric characters in the url|
|src_request_rate|request rate|
