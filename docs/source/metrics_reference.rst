Metrics Reference
=================

Metrics exposed by the Fabric CA include *labels* to differentiate various
characteristics of the item being measured. Five different labels are used.

  api_name
    For API requests, this is the path of the requested resource with the version
    prefix removed. The list of resource paths can be found in the
    `Swagger API Documentation <https://github.com/hyperledger/fabric-ca/blob/master/swagger/swagger-fabric-ca.json>`_.
    Examples include ``cainfo``, register``, and ``enroll``.

  ca_name
    The name of the certificate authority associated with the metric.

  db_api_name
    For database requests, this contains the SQL operation that was used.
    Examples include ``Commit``, ``Exec``, ``Get``, ``NamedExec``, ``Select``,
    and ``Queryx``

  func_name
    For database access, this includes the name of the function that initiated
    the database request. Examples include ``GetUser``, ``InsertUser``,
    ``LoginComplete``, and  ``ResetIncorrectLoginAttempts``.

  status_code
    For API requests, this is the HTTP status code of the response. Successful
    requests will have status codes that are less than 400.

Prometheus Metrics
------------------

The following metrics are currently exported for consumption by Prometheus.

+-------------------------+-----------+------------------------------------------------------------+--------------------+
| Name                    | Type      | Description                                                | Labels             |
+=========================+===========+============================================================+====================+
| api_request_count       | counter   | Number of requests made to an API                          | ca_name            |
|                         |           |                                                            | api_name           |
|                         |           |                                                            | status_code        |
+-------------------------+-----------+------------------------------------------------------------+--------------------+
| api_request_duration    | histogram | Time taken in seconds for the request to an API to be      | ca_name            |
|                         |           | completed                                                  | api_name           |
|                         |           |                                                            | status_code        |
+-------------------------+-----------+------------------------------------------------------------+--------------------+
| db_api_request_count    | counter   | Number of requests made to a database API                  | ca_name            |
|                         |           |                                                            | func_name          |
|                         |           |                                                            | dbapi_name         |
+-------------------------+-----------+------------------------------------------------------------+--------------------+
| db_api_request_duration | histogram | Time taken in seconds for the request to a database API to | ca_name            |
|                         |           | be completed                                               | func_name          |
|                         |           |                                                            | dbapi_name         |
+-------------------------+-----------+------------------------------------------------------------+--------------------+


StatsD Metrics
--------------

The following metrics are currently emitted for consumption by StatsD. The
``%{label_name}`` nomenclature indicates the location of a label value in the
bucket name.

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
