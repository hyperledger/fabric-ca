Metrics Reference
=================

Prometheus Metrics
------------------

The following metrics are currently exported for consumption by Prometheus.

+-----------------------------------------------------+-----------+------------------------------------------------------------+--------------------+
| Name                                                | Type      | Description                                                | Labels             |
+=====================================================+===========+============================================================+====================+
| api_request_duration                                | histogram | Time taken in seconds for the request to an API to be      | api_name ca_name   |
|                                                     |           | completed.                                                 | status_code        |
+-----------------------------------------------------+-----------+------------------------------------------------------------+--------------------+
| api_request_count                                   | counter   | Number of request made to an API.                          | api_name ca_name   |
|                                                     |           |                                                            | status_code        |
+-----------------------------------------------------+-----------+------------------------------------------------------------+--------------------+

StatsD Metrics
--------------

The following metrics are currently emitted for consumption by StatsD. The
``%{variable_name}`` nomenclature represents segments that vary based on
context.

For example, ``%{ca_name}`` will be replaced with the name of the ca
associated with the metric.

+-----------------------------------------------------------------------------------------+-----------+------------------------------------------------------------+
| Bucket                                                                                  | Type      | Description                                                |
+=========================================================================================+===========+============================================================+
| api_request_duration.%{ca_name}.%{api_name}.%{status_code}                              | histogram | Time taken in seconds for the request to an API to be      |
|                                                                                         |           | completed.                                                 |
+-----------------------------------------------------------------------------------------+-----------+------------------------------------------------------------+
| api_request_count.%{ca_name}.%{api_name}.%{status_code}                                 | counter   | Number of request made to an API.                          |
|                                                                                         |           |                                                            |
+-----------------------------------------------------------------------------------------+-----------+------------------------------------------------------------+
