Metrics Reference
=================

Prometheus Metrics
------------------

The following metrics are currently exported for consumption by Prometheus.

+-------------------------+-----------+------------------------------------------------------------+--------------------------------------------------------------------------------+
| Name                    | Type      | Description                                                | Labels                                                                         |
+=========================+===========+============================================================+=============+==================================================================+
| api_request_count       | counter   | Number of requests made to an API                          | ca_name     |                                                                  |
|                         |           |                                                            +-------------+------------------------------------------------------------------+
|                         |           |                                                            | api_name    | example api_names: affiliations/{affiliation}, affiliations,     |
|                         |           |                                                            |             | certificates, enroll, reenroll, gencrl, idemix/cri, identities,  |
|                         |           |                                                            |             | register, revoke, idemix/credential, identities/{id}.            |
|                         |           |                                                            +-------------+------------------------------------------------------------------+
|                         |           |                                                            | status_code | Http status code.                                                |
|                         |           |                                                            |             | https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html          |
+-------------------------+-----------+------------------------------------------------------------+-------------+------------------------------------------------------------------+
| api_request_duration    | histogram | Time taken in seconds for the request to an API to be      | ca_name     |                                                                  |
|                         |           | completed                                                  +-------------+------------------------------------------------------------------+
|                         |           |                                                            | api_name    | example api_names: affiliations/{affiliation}, affiliations,     |
|                         |           |                                                            |             | certificates, enroll, reenroll, gencrl, idemix/cri, identities,  |
|                         |           |                                                            |             | register, revoke, idemix/credential, identities/{id}.            |
|                         |           |                                                            +-------------+------------------------------------------------------------------+
|                         |           |                                                            | status_code | Http status code.                                                |
|                         |           |                                                            |             | https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html          |
+-------------------------+-----------+------------------------------------------------------------+-------------+------------------------------------------------------------------+
| db_api_request_count    | counter   | Number of requests made to a database API                  | ca_name     |                                                                  |
|                         |           |                                                            +-------------+------------------------------------------------------------------+
|                         |           |                                                            | func_name   |                                                                  |
|                         |           |                                                            +-------------+------------------------------------------------------------------+
|                         |           |                                                            | dbapi_name  | example dbapi_names: affiliations/{affiliation}, affiliations,   |
|                         |           |                                                            |             | certificates, enroll, reenroll, gencrl, idemix/cri, identities,  |
|                         |           |                                                            |             | register, revoke, idemix/credential, identities/{id}.            |
+-------------------------+-----------+------------------------------------------------------------+-------------+------------------------------------------------------------------+
| db_api_request_duration | histogram | Time taken in seconds for the request to a database API to | ca_name     |                                                                  |
|                         |           | be completed                                               +-------------+------------------------------------------------------------------+
|                         |           |                                                            | func_name   |                                                                  |
|                         |           |                                                            +-------------+------------------------------------------------------------------+
|                         |           |                                                            | dbapi_name  | example dbapi_names: affiliations/{affiliation}, affiliations,   |
|                         |           |                                                            |             | certificates, enroll, reenroll, gencrl, idemix/cri, identities,  |
|                         |           |                                                            |             | register, revoke, idemix/credential, identities/{id}.            |
+-------------------------+-----------+------------------------------------------------------------+-------------+------------------------------------------------------------------+


StatsD Metrics
--------------

The following metrics are currently emitted for consumption by StatsD. The
``%{variable_name}`` nomenclature represents segments that vary based on
context.

For example, ``%{channel}`` will be replaced with the name of the channel
associated with the metric.

+---------------------------------------------------------------+-----------+------------------------------------------------------------+
| Bucket                                                        | Type      | Description                                                |
+===============================================================+===========+============================================================+
| api_request.count.%{ca_name}.%{api_name}.%{status_code}       | counter   | Number of requests made to an API                          |
+---------------------------------------------------------------+-----------+------------------------------------------------------------+
| api_request.duration.%{ca_name}.%{api_name}.%{status_code}    | histogram | Time taken in seconds for the request to an API to be      |
|                                                               |           | completed                                                  |
+---------------------------------------------------------------+-----------+------------------------------------------------------------+
| db_api_request.count.%{ca_name}.%{func_name}.%{dbapi_name}    | counter   | Number of requests made to a database API                  |
+---------------------------------------------------------------+-----------+------------------------------------------------------------+
| db_api_request.duration.%{ca_name}.%{func_name}.%{dbapi_name} | histogram | Time taken in seconds for the request to a database API to |
|                                                               |           | be completed                                               |
+---------------------------------------------------------------+-----------+------------------------------------------------------------+


.. Licensed under Creative Commons Attribution 4.0 International License
   https://creativecommons.org/licenses/by/4.0/
